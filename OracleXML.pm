package OracleXML;
use strict;
use XML::LibXML::Simple   qw(XMLin);
use Data::Dumper::Concise;
use Rules;
use Policy;


sub new {
  my ($class,$file)=@_;
  my $self = {file=>$file};
  bless $self, $class;

  $self->{xml}=XMLin($file,ForceArray => ['rule','policy','profile-att']);
  $self->{app}=$self->{xml}->{application};
  $self->{filters}=Rules->new($self->{app}->{authorization}->{rule});

  return $self;
}

sub File {
  my $self=shift;
  return $self->{file};
}

sub LookupFilter {
  my ($self,$string)=@_;
  $self->{filters}->Lookup($string);
}

sub Host {
  my $self=shift;
  $self->{xml}->{application}->{authHost};
}

sub EnvID {
  my $self=shift;
  warn "change call from EnvID to Lane\n";
  $self->{xml}->{environment}->{id};
}

sub Lane {
  my $self=shift;
  $self->{xml}->{environment}->{id};
}

sub AppID {
  my $self=shift;
  warn "change call from AppID to URL\n";
  $self->{xml}->{application}->{id};
}

sub URL {
  my $self=shift;
  $self->{xml}->{application}->{id};
}

sub HostEnv {
  my $self=shift;
  warn "remove call to HostEnv\n";
  return $self->HostWithLaneInserted;
}

sub HostWithLaneInserted {
  my $self=shift;
  my $lane=$self->Lane;
  return $self->Host=~s/\./-$lane./r;
}

sub DefaultPolicy {
  my $self=shift;
  Policy->new({
    name=>"default",
    url=>"*",
    parent=>$self,
    operations => "HEAD,DELETE,POST,GET,OPTIONS,PATCH,PUT",
    authentication => $self->{app}->{authentication},
    authorization => {
        "headers"=>$self->{app}->{authorization}->{default}->{headers},
        "value"=>$self->{app}->{authorization}->{default}->{value}
    }
  });
}


#my $policy_match=quotemeta("{/.../*,*}")."|".quotemeta("*{/.../*,*}");
#$policy_url=~s/($policy_match)/#/g;

my $ign="(Standard Files|SSOS|Sign-In|Sign-Out)";

sub GetPolicies {
  my $self=shift;
  my $policies=[$self->DefaultPolicy];
  if($self->{app}->{policy}) {
    foreach my $name (keys $self->{app}->{policy}) {
      next if $name=~/$ign/i;
      #next if (grep {$name eq $_} @ignore);
      my $path=$self->{app}->{policy}->{$name}->{url};
#      next if(!$url);
#      warn "empty url in ". $self->File . ": policy=$name\n";
      push($policies,Policy->new({
          name=>$name,
          url=>$path,
          parent=>$self,
          xml=>$self->{app}->{policy}->{$name}
      }));
      #warn Dumper($policy_url);
    #  warn "Policy name $name: ".$self->{app}->{policy}->{$name}->{url}."\n";
    }
  }
  #warn Dumper($policies);
  return $policies;
}

1;
