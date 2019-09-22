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

sub Context {
  my $self=shift;
  $self->{xml}->{application}->{cctx};
}

sub File {
  my $self=shift;
  return $self->{file};
}

sub LookupFilter {
  my ($self,$string,$type)=@_;
  $self->{filters}->Lookup($string,$type);
}

sub Host {
  my $self=shift;
  $self->{xml}->{application}->{authHost};
}

sub Lane {
  my $self=shift;
  $self->{xml}->{environment}->{id};
}

sub URL {
  my $self=shift;
  $self->{xml}->{application}->{id};
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

my $ign="(Standard Files|SSOS|Sign-In|Sign-Out)";

sub GetPolicies {
  my $self=shift;
  my $policies=[$self->DefaultPolicy];
  if($self->{app}->{policy}) {
    foreach my $name (keys $self->{app}->{policy}) {
      next if $name=~/$ign/i;
      my $path=$self->{app}->{policy}->{$name}->{url};
      push($policies,Policy->new({
          name=>$name,
          url=>$path,
          parent=>$self,
          xml=>$self->{app}->{policy}->{$name}
      }));
    }
  }
  return $policies;
}

1;
