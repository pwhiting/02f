package Rules;
use strict;
use Data::Dumper::Concise;
use Scalar::Util qw/reftype/;
use Bypass;
use Rule;

sub new {
  my ($class,$xmlin)=@_;
  my $self = {};
  bless $self, $class;
  $self->MakeFilters($xmlin);
  return $self;
}

sub GetCondition {
  my ($condition)=@_;
  return undef if reftype $condition ne reftype {};
  return $condition->{content}=~s/.*?(\(.*\)).*/$1/r if($condition->{type} eq "ldap");
  return "" if $condition->{type} eq "role" && $condition->{value} eq "Anyone";
  warn "Condition not handled: ".Dumper($condition);
  return undef;
}

sub MakeFilters {
  my ($self,$rules)=@_;
  foreach my $rule (keys $rules) {
    next if $rule=~/~~default-headers~~/;
    $self->{rulehash}->{$rule=~s/\&/and/gr}= Rule->new(
      allow=>GetCondition($rules->{$rule}->{allow}->{condition}),
      deny=>GetCondition($rules->{$rule}->{deny}->{condition}),
      precedence=>($rules->{$rule}->{"allow-takes-precedence"} eq "true"),
    );
  }
}

sub LookupFilter {
  my ($self,$rule)=@_;
  return $Bypass::rule->{$rule} if($Bypass::rule->{$rule});
  my ($opr,@rules) = ParseRuleName($rule);
  if ($opr) {
    return "($opr" . join("",(map {$self->LookupFilter($_)} @rules)) . ")";
  }
  if (! defined $self->{rulehash}->{$rule} ) {
    warn "undefined rule named $rule\n";
    return "undefined";
  }
  return $self->{rulehash}->{$rule}->Filter;
}

sub LookupShape {
  my ($self,$rule)=@_;
  return "X" if($Bypass::rule->{$rule});
  my ($opr,@rules) = ParseRuleName($rule);
  if ($opr) {
    return join(" $opr ",(map {$self->LookupShape($_)} @rules));
  }
  if (! defined $self->{rulehash}->{$rule} ) {
    warn "undefined rule named $rule\n";
    return "undefined";
  }
  return $self->{rulehash}->{$rule}->Shape;
}

# below we need to transform the \& in the policy reference to
# the rule name because it includes a \ and the rule name
# didn't include that when being created above
sub ParseRuleName {
  my ($rule)=@_;
  $rule=~s/\\\&/and/g;
  if($rule=~/\s+([\|\&])\s+/) {
    my $opr=$1;
    return $opr,(split /\s+\Q$opr\E\s+/, $rule);
  }
  return undef;
}

1;

__END__
