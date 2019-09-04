package Policy;
use JSON::MaybeXS ();
use strict;
use Rules;
use Data::Dumper::Concise;
use CamoMap;
sub new {
  my ($class,$args)=@_;
  my $self = {
    name=>$args->{name},
    parent=>$args->{parent},
    authorization=>$args->{authorization} || $args->{xml}->{authorization},
    authentication=>$args->{authentication} || $args->{xml}->{authentication},
    operations=>$args->{operations} || $args->{xml}->{operations}
  };
  $self->{shortname}=$self->{name}=~s/\{.*//r;
  bless $self, $class;
  return $self;
}

sub Filter {
  my $self=shift;
  $self->{parent}->LookupFilter($self->{authorization}->{value});
}

sub Scheme {
  my $self=shift;
  $self->{authentication}->{scheme};
}

# check below - does this really need to be hostenv, as that doesn't
# show up in the xml file anywhere.
sub URL {
  my $self=shift;
  "http*://" . $self->{parent}->HostEnv . ":*/" .
    (($self->{shortname} ne "default")?$self->{shortname}:"");
};

sub Resources {
  my $self=shift;
  [$self->URL . "*?*", $self->URL . "*"];
}

sub Name {
  my $self=shift;
  $self->{name};
}


sub ResourceAttributes {
  my $self=shift;
  my $profile=
    $self->{authorization}->{headers}->{success}->{"profile-att"};
  return if !$profile;
  my @list=map {$profile->{$_}->{attribute}} (keys $profile);
  my $array=[];
  map {push($array,{
      propertyName  => CamoMap::recase($_),
      type          =>"User",
      propertyValues=>[]})} @list;
  $array;
}

# input: array of action actionValues
# output: hash reference with each actionvalue set to true
sub ActionValues {
  my $self=shift;
  my @list=split(/[,\"]/,$self->{operations});
  @list=qw(HEAD DELETE POST GET OPTIONS PATCH PUT) if !@list;
  my $hash={};
  map {$hash->{$_}=JSON::MaybeXS::true} @list;
  return $hash;
}

sub Path {
  my $self=shift;
  my $name=$self->{parent}->ID . "/" . $self->{parent}->Host;
  $name.="/$self->{shortname}" if $self->{name} ne "default";
  return $name=~s/\//\!/gr;
}

sub Subjects {
  my $self=shift;
  return ($self->Scheme eq "anonymous")?
    {type=>"NOT",subject=>{type=>"NONE"}}: # should be subjects? (plural)
    {type=>"AND",subjects=>[{type=>"AuthenticatedUsers"}]};
}

sub Conditions {
  my $self=shift;
  if($self->Scheme ne "anonymous") {
    my $filter=$self->Filter;
    my $authlevel=200;
    my $cond=[];
    push($cond,{type=>"AuthLevelFlow",authLevel=>$authlevel}) if $authlevel;
    push($cond,{type=>"LDAPFilter",ldapFilter=>$filter}) if $filter;
    return {type=>"AND",conditions=>$cond};
  }
  return {conditions=>[]};
}

1;
