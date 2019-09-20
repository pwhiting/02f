package Policy;
use JSON::PP ();
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


  # may need to rethink this - it replaces {/.../*,*} with *
  # and some of these are in a few policies {*/.../*,*}
   $self->{url}=~s/\*?\{\*?\/\.\.\.\/\*\,\*\}//g;
   warn "unknown syntax: ". $self->{url}."\n" if ($self->{url}=~/\/\.\.\.\/\*/);
   $self->{url}=~s/\/\.\.\.\/\*/\/\*/g;

   $self->{url}=~s/\/+/\//g;

  #$self->{url}=~s/\*+/\*/g;
  ## this is the right place to get the expansion ready, not
  ## below in ExpandResources
  ##-*-
  #$self->{url}=~s/\*?\.\.\.\/?\*?/-*-/g;

#  $self->{url}=~s/\.\.\.\/?/\*/g;




  bless $self, $class;
  $self->Resources;
  $self->Attributes;
  return $self;
}

sub Merge {
  my $self=shift;
  my $sibling=shift;
  push($self->Resources,@{$sibling->Resources});
  foreach my $attr (@{$sibling->Attributes}) {
    $self->{attributes}->{$attr}+=
      $sibling->{attributes}->{$attr};
  }
}

sub Filter {
  my $self=shift;
  my $filter=$self->{parent}->LookupFilter($self->FilterName);
  return ($filter eq "(*)" ) ? "": $filter;
}

sub FilterName {
  my $self=shift;
  my %args=@_;
  my $name=$self->{authorization}->{value};
  if($args{invert}){
    $name=~s/Allow//g;
    $name="Deny everyone but: ($name)";
  }
  return $name;
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

sub Attributes {
  my $self=shift;
  return [keys $self->{attributes}] if defined $self->{attributes};
  my $attrs=$self->{authorization}->{headers}->{success}->{"profile-att"};
  return [] if(!$attrs);
  foreach my $key (keys $attrs) {
    $self->{attributes}->{CamoMap::recase($attrs->{$key}->{attribute})}=1;
  }
  return [keys $self->{attributes}];
}

sub ResourceAttributes {
  my $self=shift;
  return [map {{propertyName=>$_,type=>"User",propertyValues=>[]}}
              @{$self->Attributes}];
}

sub Attributes1 {
  my $self=shift;
  $self->{attributes}=[];
  print Dumper($self->{authorization}->{headers}->{success}->{"profile-att"});
  if(my $profile=$self->{authorization}->{headers}->{success}->{"profile-att"}) {
      $self->{attributes}=[map {CamoMap::recase($profile->{$_}->{attribute})}
        (keys $profile)];
  }
  #print Dumper($self->{attributes});
  return $self->{attributes};
}

# /.../ -> *?
sub Resources {
  my $self = shift;
  $self->{resources} = $self->ExpandResources("http*://" . $self->{parent}->URL.$self->URL)
    if(!defined $self->{resources});
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
    $url=~s/\*+/*/g; # not sure why it needs /g to work...
    if($url=~/\*$/) {
      $list=[$url,"$url?","$url?*"];
    } else {
      $list=[$url];
    }
  }
  return $list;
}

sub Name {
  my $self=shift;

  return $self->{name};
}



# input: array of action actionValues
# output: hash reference with each actionvalue set to true
sub ActionValues {
  my $self=shift;
  my %args=@_;
  my $value=($args{invert})?JSON::PP::false : JSON::PP::true;
  my @list=split(/[,\"]/,$self->{operations});
  @list=qw(HEAD DELETE POST GET OPTIONS PATCH PUT) if !@list;
  my $hash={};
  map {$hash->{$_}=$value} @list;
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

# returns a properly formed Conditions hash in compliance with what
# ForgeRock expects in it's JSON file. If the scheme is anonymous an
# emply hash reference is returned. If that doesn't work for ForgeRock,
# the caller needs to delete it from the resulting JSON;
sub Conditions {
  my $self=shift;
  my %args=@_;
  if($self->Scheme ne "anonymous") {
    my $filter=$self->Filter;
    return [] if !$filter && $args{invert};  #this needs work - what to do if the query is empty? you want to deny all non-authenticated users, so maybe have logic to do this in the subject section and not here
    my $authlevel=200;
    $filter="(!($filter))" if $args{invert};
    my $cond=[];
    push($cond,{type=>"AuthLevelFlow",authLevel=>$authlevel}) if $authlevel;
    push($cond,{type=>"LDAPFilter",ldapFilter=>$filter}) if $filter;
    return {type=>"AND",conditions=>$cond};
  }
  return {conditions=>[]};
}

1;
