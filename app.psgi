use Plack::Builder;
use Plack::Request;
use Plack::App::Proxy;
use Plack::App::File;
use Plack::App::Directory;
use Plack::Middleware::DirIndex;
use Plack::Util;
use Plack::Session;
use Plack::Session::State::Cookie;

use URI;
use URI::Escape;
use MIME::Base64;
use HTML::Template;

use lib './lib'; # local library

use Plack::Middleware::Sentinel;
use Plack::Middleware::ReqLog;
use Plack::Middleware::HostSwitch;
use Plack::Middleware::LocationProxy;

require Secrets;

my $apikey = sub {
	my $app = shift;
	sub {
		my $env = shift;
		my $req = Plack::Request->new($env);

		return $app->($env) if $env->{login};
		if($req->headers->header('authorization') =~ m/^bearer +([a-z0-9]+)$/i){
			if(my $uname = &DATA->login_apikey($1)){
				$env->{login} = $uname;
				return $app->($env);
			}
			return [401, [], ["invalid apikey!"]];
		}
		return $app->($env);
	};
};

sub template_login_page {
	my $templ = HTML::Template->new(filename => "./templates/login.html");
	$templ->param(REDIRECT => shift);
	return $templ->output;
}

sub template_session_terminated {
	my $templ = HTML::Template->new(filename => "./templates/terminated.html");
	return $templ->output;
}

sub template_overview {
	my $templ = HTML::Template->new(filename => "./templates/overview.html");
	$templ->param(USER => shift);
	$templ->param(AREAS => shift);
	return $templ->output;
}

my $session_terminator = sub {
	my $app = shift;
	sub {
		my $env = shift;
		my $req = Plack::Request->new($env);

		if($req->method eq "GET" and $req->path eq "/terminate") {
			if(my $terminator = $env->{QUERY_STRING}) {
				if(&DATA->terminate_token($terminator)){
					return [200, ["content-type" => "text/html"], [template_session_terminated()]];
				}
				return [404, ["content-type" => "text/plain"], ["session not found!"]];
			}
			return [400, ["content-type" => "text/plain"], ["malformed request!"]];
		}

		return $app->($env);
	};
};

my $password = sub {
	my $app = shift;
	sub {
		my $env = shift;
		my $req = Plack::Request->new($env);
		my $session = Plack::Session->new($env);

		if($req->method eq "GET" and $req->path eq "/login") {
			$session->expire();
			my $url = URI->new($req->query_parameters->{"redirect"} || $self->{redirect} || "/sub/mclip"); # redirect to api. subdomain if no path has been chosen
			if($url->path eq "/login") { # prevent a login, logout loop ...
				return [400, ["content-type" => "text/plain"], ["malformed request!"]];
			}
			return [200, ["content-type" => "text/html", "cache-control" => "no-cache"], [ template_login_page($url->path_query) ]];
		}

		if($req->method eq "POST" and $req->path eq "/login") {
			if($req->headers->header('authorization') =~ m/^basic +([a-z0-9+\/]+=*)$/i){
				my ($uname, $pwd) = split ":", decode_base64($1), 2;
				if(my $login = &DATA->login_password($uname, $pwd)){
					print "logged in as $login!\n";
					$session->set('expiration', time() + 31536000); # database expiration one year
					my $terminator = &SID_GENERATOR->();
					$session->set('terminator', $terminator);
					$session->set('login', $login);
					&ON_USER_LOGIN->($terminator);
					return [200, ["content-type" => "text/plain"], ["login successful!"]];
				}
				return [401, ["content-type" => "text/plain"], ["invalid credentials!"]];
			}
			return [400, ["content-type" => "text/plain"], ["malformed request!"]];
		}

		return $app->($env);
	};
};

my $redirect_to_subdomain = sub {
	my $app = shift;
	sub {
		my $env = shift;
		if(my ($sub, $path) = $env->{PATH_INFO} =~ /\/sub\/([a-z]+)(\/.+)?/){
			return [ 307, ["Location" => &PROTOCOL."://$sub.".&DOMAIN.$path], []];
		}
		return $app->($env);
	};
};

my $redirect_to_login = sub {
	my $app = shift;
	sub {
		my $env = shift;
		my $req = Plack::Request->new($env);
		my $session = Plack::Session->new($env);
		
		unless($session->get('login')){ # TODO use redirect_to_area middleware to correctly target area
			my $redirect = uri_escape(URI->new($req->uri)->path_query);
			return [307, ["location" => "/login?redirect=$redirect"], []];
		}
		return $app->($env);
	};
};

my $login = sub {
	my $app = shift;
	return builder {
		enable "Session",
			store => &SESSION_STORE, 
			state => Plack::Session::State::Cookie->new(
				sid_generator => &SID_GENERATOR,
				sid_validator => qr/\A[0-9a-z]{15}\Z/, 
				domain => &DOMAIN, 
				httponly => 1,
				secure => 1, 
				samesite => 'strict',
				expires => 31536000 # one year
			);
		enable $password;
		enable $redirect_to_login;
		$app;
	};
};

my $mclip = builder {
	enable "Sentinel", perm => "mclip_owner";
	enable "LocationProxy", host => &HOST_MCLIPD;
	mount "/" => Plack::App::Proxy->new(remote => &HOST_MCLIPD)->to_app;
};

my $logd = builder {
	enable "Sentinel", perm => "logd_owner";
	enable "LocationProxy", host => &HOST_LOGD;
	mount "/" => Plack::App::Proxy->new(remote => &HOST_LOGD)->to_app;
};

builder {
	enable "ReqLog", logger => &LOG_REQUEST;
	enable $session_terminator;
	enable $apikey;
	enable_if { shift->{login} eq undef } $login; # prompt for password if no login via apikey has occured
	enable "Sentinel",
		get_uid         => \&get_uid,
		get_permissions => \&get_permissions; # authenticated?, load permissions to env
	enable $redirect_to_subdomain;
	enable "HostSwitch", host => "api.".&DOMAIN, next => sub { return [307, ["Location" => "/sub/mclip"], []] };
	enable "HostSwitch", host => "mclip.".&DOMAIN, next => $mclip; # mclip
	enable "HostSwitch", host => "log.".&DOMAIN, next => $logd; # logd
	sub { return [ 404, ["content-type" => "text/plain"], ["nothing to see here ..."]]; };
};

# Sentinel

sub get_uid {
	my $env = shift;
	if(my $uname = $env->{'psgix.session'}->{login} || $env->{login}){
		return $uname;
	}
	return undef;
}

sub get_permissions {
	my $uid = shift;
	my @permissions = &DATA->get_user_groups($uid);
	return \@permissions;
}