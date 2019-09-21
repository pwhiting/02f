package ForgeRockSort;
use JSON::PP;

# This module defines a sort order for the output JSON, which isn't
# alphabetical. It is a bit obtuse, but all you need to know is that
# you can call sort_by($ForgeRockSort::sorter) on the json object
# and it will adhere to the follwing order. The words below are always
# considered before a word that doesn't exist in the list. If two words
# don't exist in the list they will be sorted alphabetically.

my %order = (
  active              => 1,
  description         => 2,
  applicationName     => 3,
  resourceTypeUuid    => 4,
  name                => 5,
  resources           => 6,
  subject             => 7,
  condition           => 8,
  actionValues        => 9,
  resourceAttributes  => 10,
  type                => 11,
  subjects            => 12,
  subject             => 13,
  authlevel           => 14,
  ldapFilter          => 15,
  conditions          => 16
  );
our $sorter = sub {
  ($order{$JSON::PP::a} // 100) <=> ($order{$JSON::PP::b} // 100)
  or $JSON::PP::a cmp $JSON::PP::b;
};

1;
