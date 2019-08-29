package Forge;
# this package creates forgerock specific JSON elements
use Data::Dumper::Concise;
use CamoMap;


# intput: reference to a policy
# output: array of attributes in that policy
sub Attributes {
  my $policy=shift;
  my $profile=$policy->{authorization}->{headers}->{success}->{"profile-att"};
  map {$profile->{$_}->{attribute}} (keys $profile);
}

# intput: reference to a policy
# output: array of operations in that policy
sub Operations {
  my $policy=shift;
  split(/[,\"]/,$policy->{operations});
}

# input: array of action actionValues
# output: hash reference with each actionvalue set to true
sub ActionValues {
  my $hash={};
  my @list=Operations(shift);
  foreach my $action (@list) {
    $hash->{$action}="true";
  }
  $hash;
}

#input: array of ResourceAttributes
#output: array reference with each attribute properly defined
sub ResourceAttributes {
  my $array=[];
  my @list=Attributes(shift);
  foreach my $attr (@list) {
    push($array,{
      propertyName  => CamoMap::recase($attr),
      type          =>"User",
      propertyValues=>[]
    });
  }
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
  my $hash={
    type=>"AND",
    "subjects"=>[
      {
        "type"=>"AuthenticatedUsers"
      }
    ]
  };
  $hash;
}

#stub for now
sub Condition {
    my $hash={
      type=>"AND",
      "conditions" => [
      {
        "type" => "AuthLevelFlow",
        "authLevel" => 200
      },
      {
        "type" => "LDAPFilter",
        "ldapFilter"=> "(&(!(ldsisAnonymous=*))(ldsmrn=*))"
      }
    ]
  };
  $hash;
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
