package Rules;
use strict;
use Data::Dumper::Concise;
use Scalar::Util qw/reftype/;
use Bypass;

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
    $expr.=$1 if $condition->{content}=~/(\(.*\))/;
  } elsif ($condition->{type} eq "role") {
    $expr.="*"if $condition->{value} eq "Anyone";
  }
  return "$expr";
}

sub EscapeRuleName {
  my $name=shift;
  return $name=~s/\&/and/rg;
}
# this is a quirk - the oracle policy exscape the rule name
# differently when listed in a policy
sub EscapeRuleNameInPolicy {
  my $name=shift;
  return $name=~s/\Q\&/and/rg;
}
#input: hash reference of rules, each hash key being a rule name
#       Everything within the hash follows the xml export from Oracle.
#output: hash reference where each key is the rule name and the value
#        is the ldap expression which will match the exported rule.
#        allow everything is returned as (*) and deny everything as (!*)
sub MakeFilters {
  my ($self,$rules)=@_;
  my $allow="*";
  my $deny="!*"; # this needs to change
  foreach my $rule (keys $rules) {
    next if $rule=~/~~default-headers~~/;
  #  my $erule=EscapeRuleName($rule);
#  warn "rule name is $rule.\n";
    my $filter="";
    my $A=GetExpr($rules->{$rule}->{allow}->{condition});
    my $D=GetExpr($rules->{$rule}->{deny}->{condition},"!");
    my $atp=($rules->{$rule}->{"allow-takes-precedence"} eq "true");

#    warn "rule $rule A=$A\n";
#    warn "raw $rule Allow". Dumper($rules->{$rule}->{allow}->{condition}) .".\n";
#    warn "raw $rule Deny". Dumper($rules->{$rule}->{deny}->{condition}) .".\n";
#    warn "rule $rule D=$D\n";

    my $a=($A)?"A":"_";
    $a="*" if($A eq $allow);
    my $d=($D)?"D":"_";
    $d="#" if($D eq $deny);
    my $p=($atp)?"t":"f";

    #put erule
    $self->{$rule}->{expr}="$a $d $p";

    #if($d eq "D" and $a eq "A" and $atp) {$filter="|($D)$A";}
    if(!$A) {$filter=$deny;}
    elsif($atp) {$filter=$A;}
    elsif(!$D) {$filter=$A;}
    elsif($A eq $allow || $D eq $deny) {$filter=$D;}
    else {$filter="&($D)$A";}

#    warn "setting $rule to $filter\n";
    #$self->{$erule}->{filter}="(". lc($filter). ")";
    $self->{$rule}->{filter}="(". lc($filter). ")";

  }
}


sub Lookup {
  my ($self,$rule,$type)=@_;
  $type="filter" if not $type;

  if($Bypass::rule->{$rule}) {
    return "X" if $type eq "expr";
    return $Bypass::rule->{$rule};
  }

  #$rule=EscapeRuleNameInPolicy($rule);
#  print "processing $rule\n";

  if($rule=~/\s+([\|\&])\s+/) {
    my $opr=$1;
    my @keys=map {s/\\\&/\&/rg} (split /\s+\Q$opr\E\s+/, $rule);
  #  my @keys=(split /\s+\Q$opr\E\s+/, $rule);

#    print "split:".join(":",@keys).".\n";
    if($type eq "filter") {
      return "($opr" . join("",(map {$self->{$_}->{$type}} @keys)) . ")";
    } else {
      return join(" $opr ",(map {$self->{$_}->{$type}} @keys));
    }
  } else {
    return $self->{$rule}->{$type};
  }
}


sub new {
  my ($class,$xmlin)=@_;
  my $self = {};
  bless $self, $class; #self is now Rules class
  $self->MakeFilters($xmlin);
  return $self;
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
(A) (!) f -> (!)  --- never occurs
(A) (D) t -> (A)  --- A&D allow: allow men deny: deny under 12 (!age<12) -> (gender=man)&(!age<12)
(A) (D) f -> A&D
(A) ( ) t -> (A)
(A) ( ) f -> (A)  --- 75 matches

( ) (!) t -> (!)
( ) (!) f -> (!)
( ) (D) t -> (!)
( ) (D) f -> (!)
( ) ( ) t -> (!)
( ) ( ) f -> (!)

One way to process the above would be with 18 if statements.
However, there is an easier way:

if A is empty then deny
if $allow_takes_prcedence then filter = A
else {
 if d is empty d=A
 if A and D are different and A!=(*) and D!=(!) then set filter=A&D
 else filter=D
}

9/22/2019: ptw - may need to rethink the above for places where two rulesets are combined
