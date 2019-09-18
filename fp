#!/usr/bin/perl
use OracleXML;
use Policy;
use strict;
use Data::Dumper::Concise;

my $hash={};
my $group={};

foreach my $file (@ARGV) {
  warn "processing $file\n";
  my $oracle=OracleXML->new($file);
  my $top;
  foreach my $policy (@{$oracle->GetPolicies}) {
    foreach my $resource (@{$policy->Resources}) {
      $resource=~s/[\*\/]*$//;
      my $filter=$policy->Filter;
      #$group->{$policy->FilterName}=[] if(not defined $group->{$policy->FilterName});
      $group->{$filter}=[] if not defined $group->{$filter};
  #    push($group->{$policy->FilterName},($oracle->URL . $resource));
      push($group->{$filter},$resource);
    }
  }
}
print Dumper($group);
