package CamoMap;

my @attrs = qw(ldsMissionaryAssignment employeeNumber ldsCMISID ldsIsAnonymous
givenName ldsGender ldsMissionaryLanguageCode departmentNumber ldsMemberlink
telephoneNumber ldsMissionaryLanguage ldsMissionaryType ldsMissionaryId
employeeStatus ldsMissionaryEmailStatus memberOf ldsMissionaryStatus
ldsMissionaryEmailAddress employeeType);

my @map;
foreach $word (@attrs) {
  $map{lc($word)}=$word;
}

# input: attribute
# output: attribute with camocase if camo exists, otherwise original attr
sub recase {
  my $attr = shift(@_);
  $attr =$map{$attr} if($map{$attr});
  $attr;
}

1;
