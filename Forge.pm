package Forge;
# this package creates forgerock specific JSON elements
use Data::Dumper::Concise;
use CamoMap;
# input: array of action actionValues
# output: hash reference with each actionvalue set to true
sub ActionValues {
  my ($policy)=@_;
  my @list=split(/[,\"]/,$policy->{operations});
  @list=qw(HEAD DELETE POST GET OPTIONS PATCH PUT) if !@list;
  my $hash={};
  map {$hash->{$_}="true"} @list;
  $hash;
}
#input: array of ResourceAttributes
#output: array reference with each attribute properly defined
sub ResourceAttributes {
  my ($policy,$default)=@_;
  my $profile=$policy->{authorization}->{headers}->{success}->{"profile-att"};
  $profile=$default->{success}{"profile-att"} if($profile == undef);
  my @list=map {$profile->{$_}->{attribute}} (keys $profile);
  my $array=[];
  map {push($array,{
      PropertyName  => CamoMap::recase($_),
      type          =>"User",
      propertyValues=>[]})} @list;
  $array;
}
#input: name and $policy
#output: array reference with two elements, per AM standard resource naming
sub Resources {
  my ($name,$policy)=@_;
  ["http*://$name/$policy*","http*://$name/$policy*?*"];
}
#stub for now
sub Subject {
  my ($allowAnonymous)=@_;
  my $hash=($allowAnonymous)?
    {"type"=>"NOT","subject"=>"NONE"}: # should be subjects? (plural)
    {"type"=>"AND","subjects"=>[{"type"=>"AuthenticatedUsers"}]};
  $hash;
}

#stub for now
sub Condition {
  my($authlevel,$filter)=@_;
  my $cond=[];
  push($cond,{"type"=>"AuthLevelFlow","authLevel"=>$authLevel}) if $authLevel;
  push($cond,{"type"=>"LDAPFilter","ldapFilter"=>$filter}) if $filter;
  {"type"=>"AND","conditions"=>$cond};
}

# input: three arguments - env, url, and policy name
# output: replaces all / in url with ! and returns above variables
#         concatinated with ! between each. If last variable is
#         empty the concatinated string doesn't end with !
sub Name {
  pop if ! $_[2];     # remove from list if empty.
  $_[1]=~s/\//\!/gr;  # replace all / with !
  join("!",@_);       # join everything with ! inbetween
}

1;
