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

sub LookupFilter {
  my ($self,$string)=@_;
  $self->{filters}->Lookup($string);
}

sub Host {
  my $self=shift;
  $self->{xml}->{application}->{authHost};
}

sub ID {
  my $self=shift;
  $self->{xml}->{environment}->{id};
}

sub ConstructDefaultPolicy {
  my $self=shift;
  Policy->new({
    name=>"default",
    parent=>$self,
    operations => "HEAD,DELETE,POST,GET,OPTIONS,PATCH,PUT",
    authentication => $self->{app}->{authentication},
    authorization => {
        "headers"=>$self->{app}->{authorization}->{default}->{headers},
        "value"=>$self->{app}->{authorization}->{default}->{value}
    }
  });
}

sub GetPolicies {
  my $self=shift;
  my $policies=[$self->ConstructDefaultPolicy];
  if($self->{app}->{policy}) {
    foreach my $name (keys $self->{app}->{policy}) {
      next if $name=~/ /; # remove all policies with space in name
      push($policies,Policy->new({
          name=>$name,
          parent=>$self,
          xml=>$self->{app}->{policy}->{$name}
      }));
    }
  }
  $policies;
}

1;
