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
    operations=>$args->{operations} || $args->{xml}->{operations},
    url=>$args->{url},
    #shortname=>$args->{name}=~s/$remove/*/rg
  };

  $self->{url}=~s/\*?\{\/\.\.\.\/\*\,\*\}//g;
  $self->{url}=~s/\/\.\.\.\/\*/\/\*/g;

  bless $self, $class;
  $self->Resources;
  return $self;
}

sub Merge {
  my $self=shift;
  my $sibling=shift;
  push($self->Resources,@{$sibling->Resources});
}
sub Filter {
  my $self=shift;
  return $self->{parent}->LookupFilter($self->{authorization}->{value});
}

sub FilterName {
  my $self=shift;
  return $self->{authorization}->{value};
}

sub Scheme {
  my $self=shift;
  return $self->{authentication}->{scheme};
}

sub Subdirectory {
  my $self=shift;
  return $self->{url};
}

sub URL {
  my $self=shift;
  return $self->{url};
}

sub FullURL {
  my $self=shift;
  return "http*://" . $self->{parent}->URL . (($self->URL)?"/".$self->URL:"");
}

# /.../ -> *?
sub Resources {
  my $self = shift;
  $self->{resources} = $self->ExpandResources("http*://" . $self->{parent}->URL.$self->URL)
    if(!defined $self->{resources});
    #return [$self->FullURL . "*?*", $self->FullURL . "*"];
  return $self->{resources};
}

sub ExpandResources {
  my $self=shift;
  my $url=shift; # this is recursive, so has to take this
  # this needs to expand to include all possible resource matches
  # look at the url and see if it contains a set. If it does
  # expand the set to one resource for each element of the set
  #print "expanding $url\n";
  my $list=[];
  if(my ($pre,$set,$post)=$url=~/(.*?)\{(.*?)\}(.*)/){
    foreach my $item (split(",",$set)) {
        push($list,@{$self->ExpandResources($pre.$item.$post)});
    }
  } else {
    $list=[$url];
  }
  return $list;
}

sub Name {
  my $self=shift;
  return $self->{name};
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
  return $array;
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

# maybe just select the top path
sub Path {
  my $self=shift;
  my $name=$self->{parent}->EnvID . "/" . $self->{parent}->Host;
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
