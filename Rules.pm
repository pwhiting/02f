package Rules;
use strict;
use Data::Dumper::Concise;
use Scalar::Util qw/reftype/;

#input: an xml expression - one of the following 3:
# 1. <condition  type='ldap' >ldap:///ou=People,o=lds??sub?(X)</condition>
# 2. <condition  type='role' value='Anyone' />
# 3. empty (the allow or deny section didn't exist)
# an optional second argument is the character to apply to the front
#    of the extracted expression (used to negate the deny statement).
#output:
# if the condition was empty return nothing.
# if the condition was always true return (*) for allow and (!*) for deny.
# if the condition was an ldap expression X, return (X) for allow and
#    (!X) for deny.

sub GetExpr {
  my ($condition,$expr)=@_;
  return if reftype $condition ne reftype {};
  if($condition->{type} eq "ldap" ) {
    $expr.=$1 if $condition->{content}=~/\((.*)\)/;
  } elsif ($condition->{type} eq "role") {
    $expr.="*"if $condition->{value} eq "Anyone";
  }
  return "($expr)";
}

#input: hash reference of rules, each hash key being a rule name
#       Everything within the hash follows the xml export from Oracle.
#output: hash reference where each key is the rule name and the value
#        is the ldap expression which will match the exported rule.
#        allow everything is returned as (*) and deny everything as (!*)
sub MakeFilters {
  my ($rules)=(@_);
  my $hash={};
  my $allow="(*)";
  my $deny="(!*)";
#  warn Dumper($rules);
  foreach my $rule (keys $rules) {
    next if $rule=~/~~default-headers~~/;
    my $filter="";
    my $A=GetExpr($rules->{$rule}->{allow}->{condition});
    my $D=GetExpr($rules->{$rule}->{deny}->{condition},"!");
    my $atp=($rules->{$rule}->{"allow-takes-precedence"} eq "true");

# see explaination below
    if(!$A) {$A=$D;}
    if(!$D) {$D=$A;}

    if(!$A && !$D) {$filter=$deny;}
    elsif ($atp) {$filter=$A;}
    elsif (($A ne $D)&&($A ne $allow)&&($D ne $deny)) {$filter="(&$D$A)";}
    else {$filter=$D;}

    $hash->{$rule}=$filter;
  }
  $hash;
}

1;

__END__

Truth table for the 18 possible conditions

A means there is an allow expression
d means there is a deny expression (which has been negated)
* means that allow is always true
! means that deny is always true
t means allow_takes_precedence is true
f means allow_takes_precedence is false

(*) (!) t -> (*)
(*) (!) f -> (!)
(*) (D) t -> (*)
(*) (D) f -> (D)
(*) ( ) t -> (*)
(*) ( ) f -> (*)

(A) (!) t -> (A)
(A) (!) f -> (!)
(A) (D) t -> (A)
(A) (D) f -> A&D
(A) ( ) t -> (A)
(A) ( ) f -> (A)

( ) (!) t -> (!)
( ) (!) f -> (!)
( ) (D) t -> (D)
( ) (D) f -> (D)
( ) ( ) t -> (!)
( ) ( ) f -> (!)

One way to process the above would be with 18 if statements.
However, there is an easier way:

if A is empty then set A=D
if D is empty then set D=A

if A and D are still empty then set filter=false
else if allow_takes_precedence is true then set filter=A
else if A and D are different and A!=(*) and D!=(!) then set filter=A&D
else set filter = D
