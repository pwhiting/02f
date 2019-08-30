package Rules;
use Data::Dumper::Concise;


# allow-takes-percedences
# assume A is the condition which is allowed A=(A1|A2|A3)
# assume B is the condition which is denied B=(B1|B2|B3)
# assumine
#  if A and B match and allow-takes-precedense is true
#   then result is true
#   otherwise false
#  if neither A or B matches and allow-takes-precendence is true
#   then result is true
#   otherwise false
#  if A matches and B doesn't result is true
#  if B matches and A doesn't result is false
#
# if allow-takes-precedence is true result=(A|!B)
# if allow-takes-precedence is false rsult=(A&!B)

sub FixBoolean {
  my ($string)=@_;
  if($string=~/^\(([\|\x26])/) {
    my $joiner=$1;
    $string=~s/\([\|&]/\(/;
    $string=~s/\)\(/\)$joiner\(/g;
  }
  $string;
}

sub MakeFilterRules {
  my ($rules)=(@_);
  foreach my $rule (keys $rules) {
    my ($A)=$rules->{$rule}->{allow}->{condition}->{content}=~/(\(.*\))/;
    my ($B)=$rules->{$rule}->{deny}->{condition}->{content}=~/(\(.*\))/;
    my $def_allow=($rules->{$rule}->{"allow-takes-precedence"} eq "true");
    $A=FixBoolean($A);
    $B=FixBoolean($B);
    $A.=(($def_allow)?"&":"|") if($A && $B);
    $B="!$B" if($B);
    my $result="($A$B)";
    print "Expression: $result\n\n";
  }
}

1;
