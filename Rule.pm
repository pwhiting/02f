package Rule;
use strict;
use Data::Dumper::Concise;

sub IsAllowAll { my $self=shift; return $self->{allow_all};}
sub IsDenyAll { my $self=shift; return $self->{deny_all};}

sub new {
  my ($class)=shift;
  my %args=@_;
  my $self = {
    allow=>$args{allow},
    deny=>$args{deny},
    precedence=>$args{precedence},
  };
  bless $self, $class;
  $self->BuildFilter;
  $self->BuildShape;
  return $self;
}

sub BuildShape {
    my ($self)=@_;
    my $A=((not defined $self->{allow})?"_":(($self->{allow})?"A":"*"));
    my $D=((not defined $self->{deny})?"_":(($self->{deny})?"D":"#"));
    my $P=($self->{precedence})?"t":"f";
    $self->{shape}="$A $D $P";
}

sub BuildFilter {
    my ($self)=@_;

    if (! defined $self->{allow}) {$self->{deny_all}=1;}
    elsif($self->{precedence} || not defined $self->{deny}) {
      if($self->{allow}) {$self->{filter}=$self->{allow};}
      else{$self->{allow_all}=1;}
    }
    elsif(not $self->{deny}) {$self->{deny_all}=1;}
    elsif(not $self->{allow}) {$self->{filter}="!$self->{deny}";}
    else {$self->{filter}="&(!$self->{deny})$self->{allow}";}
}

sub Filter {
    my ($self)=@_;
    return "" if $self->IsDenyAll; # differentiate elsewhere
    return "" if $self->IsAllowAll; # differentiate elsewhere
    return "(".lc($self->{filter}).")";
}

sub Shape {
    my ($self)=@_;
    return $self->{shape};
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
