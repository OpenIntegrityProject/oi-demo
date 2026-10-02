#!/usr/bin/env perl
# PreToolUse hook (Bash): block git pushes that force or that target main
# or staging/*, and any run of merge_pr.sh. Backs up the deny rules in
# .claude/settings.json, which only match fixed command shapes. It reads the
# command statically, so it catches the spellings agents write, not every
# possible one: a mistake-catcher, not a security boundary. Branch
# protection and the signature verifier are the real guard.
#
# Reads the hook JSON on stdin. Exit 2 with a reason on stderr blocks the
# command; exit 0 allows it. Run via guard-git-push.sh, which fails closed
# when perl is missing.
use strict;
use warnings;

my $input = do { local $/; <STDIN> } // '';
my $command = $input;
if (eval { require JSON::PP; 1 }) {
  my $data = eval { JSON::PP::decode_json($input) };
  $command = $data->{tool_input}{command} // '' if ref $data eq 'HASH';
}

# Options of git itself that take a separate value (git -C dir push ...)
my %git_opt_with_value = map { $_ => 1 } qw(-C -c --git-dir --work-tree --namespace --exec-path);
# Options of git push that take a separate value
my %push_opt_with_value = map { $_ => 1 } qw(-o --push-option --repo --receive-pack --exec);
# git subcommands that update remote refs from <remote> <refspec>...
my %push_like = map { $_ => 1 } qw(push send-pack http-push);

# Words that may come before the real command: assignments, wrappers and
# their flags or numbers, shells (sh -c, bash <<<), and shell keywords.
my $prefix_word = qr{^(?:\w+=\S*|-\S*|\d\S*|!|\{|\}|\.
  |if|then|else|elif|do|while|until|time|source
  |(?:\S*/)?(?:sudo|env|exec|command|builtin|nohup|nice|timeout|stdbuf|xargs|eval|(?:ba|z|da|k)?sh))$}x;
my $shell = qr{(?:^|[\s/])(?:ba|z|da|k)?sh\b};
my $git_word = qr{(?:^|/)git$};
# Placeholder for a command substitution whose output can't be known
my $unknown = '$__substitution__';

sub block {
  print STDERR "guard-git-push: blocked: $_[0]. Agents push only to literal "
    . "claude/* branches without force; a human merges with merge_pr.sh.\n";
  exit 2;
}

sub in_dir {
  my ($dir, @cmd) = @_;
  my @c = ('git', (defined $dir ? ('-C', $dir) : ()), @cmd);
  open(my $saved, '>&', \*STDERR);
  open(STDERR, '>', '/dev/null');
  my $out = '';
  if (open(my $fh, '-|', @c)) {
    $out = do { local $/; <$fh> } // '';
    close $fh;
  }
  open(STDERR, '>&', $saved);
  chomp $out;
  return $out;
}

sub current_branch { in_dir($_[0], qw(symbolic-ref --quiet --short HEAD)) }

# True when a destination ref is, or as a glob could match, main or staging/*
sub protected {
  my ($ref) = @_;
  $ref =~ s{^(?:refs/)?heads/}{};
  if ($ref =~ /\*/) {
    (my $re = quotemeta $ref) =~ s/\\\*/.*/g;
    return 'main' =~ /^$re$/ || 'staging/x' =~ /^$re$/;
  }
  return $ref eq 'main' || $ref =~ m{^staging/};
}

# True when a word, possibly a glob, could name merge_pr.sh
sub is_merge_pr {
  (my $base = $_[0]) =~ s{.*/}{};
  (my $re = quotemeta $base) =~ s/\\\*/.*/g;
  $re =~ s/\\\?/./g;
  return 'merge_pr.sh' =~ /^$re$/;
}

# Shell variables assigned earlier in the command: name => [values]
my %vars;
sub expand {
  my ($word) = @_;
  my @out = ($word);
  for (1 .. 8) {
    last unless grep { /\$\{?\w+\}?/ } @out;
    my @next;
    for my $w (@out) {
      if ($w =~ /\$\{?(\w+)\}?/ && $vars{$1}) {
        my $name = $1;
        push @next, map { (my $x = $w) =~ s/\$\{?$name\}?/$_/; $x } @{ $vars{$name} };
      } else {
        push @next, $w;
      }
    }
    @out = @next;
  }
  return @out;    # anything still holding $ is unresolved
}

sub check_push {
  my ($dir, $via_xargs, @args) = @_;
  my @positional;
  for (my $j = 0; $j < @args; $j++) {
    my $w = $args[$j];
    if ($w eq '--') { push @positional, @args[$j + 1 .. $#args]; last }
    if ($w =~ /^--(?:force|mirror|all|branches)/) { block("git push $w") }
    if ($w =~ /^-[^-]*f/)                         { block("git push with -f ($w)") }
    if ($push_opt_with_value{$w})                 { $j++; next }
    next if $w =~ /^-/;
    push @positional, $w;
  }
  block("git push fed by xargs; destination can't be checked") if $via_xargs;

  my ($remote, @refspecs) = @positional;
  for my $spec (@refspecs) {
    for my $s (expand($spec)) {
      block("force refspec $s") if $s =~ /^\+/;
      my $dst = $s =~ /:/ ? (split /:/, $s, 2)[1] : $s;
      block("destination $s can't be checked; use a literal branch name") if $dst =~ /\$/;
      $dst = current_branch($dir) if $dst eq 'HEAD' || $dst eq '@';
      block("push to protected branch ($s)") if protected($dst);
    }
  }
  # With no refspec, git pushes the current branch (default push.default)
  if (!@refspecs) {
    my $branch = current_branch($dir);
    block("push from protected branch $branch") if protected($branch);
  }
}

# Check one simple command (already split at separators)
sub check_segment {
  my ($segment) = @_;
  # Remove quoting so `sh -c 'git push ...'`, "m"ain and ma\in read as the
  # shell would see them.
  (my $flat = $segment) =~ s/["'\\]//g;
  my @words = split ' ', $flat;

  # for NAME in a b c  -> NAME may be any of a b c
  if (@words >= 3 && $words[0] eq 'for' && $words[2] eq 'in') {
    push @{ $vars{$words[1]} }, @words[3 .. $#words];
    return;
  }

  # Skip to the command word, recording assignments and xargs on the way.
  # A word right after a flag may be that flag's value (sudo -iu user).
  my ($i, $via_xargs) = (0, 0);
  while ($i < @words && $words[$i] !~ $git_word && !is_merge_pr($words[$i])) {
    my $w = $words[$i];
    if    ($w =~ /^(\w+)=(.*)$/) { $vars{$1} = [$2] }
    elsif ($w =~ $prefix_word)   { $via_xargs = 1 if $w =~ m{(?:^|/)xargs$} }
    elsif ($i > 0 && $words[$i - 1] =~ /^-/ && $words[$i - 1] !~ /^-\w*c$/) { }
    else  { last }
    $i++;
  }
  return if $i >= @words;

  my @cmd = expand($words[$i]);
  block("merge_pr.sh is the human's step") if grep { is_merge_pr($_) } @cmd;
  # An unresolved command word could be git
  return unless grep { /$git_word/ || /\$/ } @cmd;
  $i++;

  my ($dir, %cli_alias);
  while ($i < @words && $words[$i] =~ /^-/) {
    my ($opt, $val) = ($words[$i], $words[$i + 1] // '');
    if ($opt eq '-C') {
      $dir = (defined $dir && $val !~ m{^/}) ? "$dir/$val" : $val;
    }
    if ($opt eq '-c' && $val =~ /^alias\.([^=]+)=(.*)$/i) {
      $cli_alias{$1} = $2;
    }
    $i += $git_opt_with_value{$opt} ? 2 : 1;
  }
  return unless $i < @words;

  my ($sub, @args) = @words[$i .. $#words];
  for my $s (expand($sub)) {
    # An unresolved subcommand could be push
    if ($push_like{$s} || $s =~ /\$/) {
      check_push($dir, $via_xargs, @args);
      next;
    }
    my $alias = $cli_alias{$s} // in_dir($dir, 'config', '--get', "alias.$s");
    next if $alias eq '';
    block("git alias $s runs a shell command that pushes") if $alias =~ /^!.*\bpush\b/;
    if ($alias =~ /^\s*(\S+)\s*(.*)$/ && $push_like{$1}) {
      check_push($dir, $via_xargs, (split ' ', $2), @args);
    }
  }
}

# Normalize: drop heredoc bodies unless a shell reads them (before joining
# continuations, so a body line ending in \ can't swallow the terminator),
# join backslash-newline continuations, read here-strings as input to
# whatever precedes them, decode $'...' quoting, and neutralize
# substitution syntax inside single quotes.
$command =~ s{^([^\n]*?<<-?\s*(['"]?)(\w+)\2[^\n]*\n)(.*?)^\s*\3\s*$}
  { my ($head, $body) = ($1, $4); $head =~ $shell ? "$head$body" : "$head\n" }gmse;
$command =~ s/\\\n//g;
$command =~ s/<<</ /g;
$command =~ s{\$'((?:[^'\\]|\\.)*)'}{
  my $s = $1;
  $s =~ s{\\x([0-9a-fA-F]{1,2})|\\([0-7]{1,3})|\\(.)}
    { defined $1 ? chr(hex $1) : defined $2 ? chr(oct $2) : $3 eq 'n' ? "\n" : $3 eq 't' ? "\t" : $3 }ge;
  $s =~ s/['"\\]//g;
  $s }ge;
$command =~ s{'[^']*'}{ (my $q = $&) =~ s/`|\$\(/ /g; $q }ge;

# Pull out command substitutions, innermost first: each is checked as a
# command of its own, and stands in its outer command as an unknown value,
# so a destination like HEAD:$(echo main) is blocked as unresolvable. The
# usual ways of naming the current branch are resolved instead.
my @commands;
for (1 .. 20) {
  last unless $command =~ s{\$\(([^()]*)\)|`([^`]*)`}{
    my $inner = $1 // $2;
    push @commands, $inner;
    $inner =~ /^\s*git\s+(?:branch\s+--show-current|rev-parse\s+--abbrev-ref\s+HEAD|symbolic-ref\s+(?:--quiet\s+)?--short\s+HEAD)\s*$/
      ? (current_branch(undef) || $unknown) : $unknown }ge;
}
push @commands, $command;

# Split into simple commands at shell separators and subshells
for my $c (@commands) {
  check_segment($_) for split /\|\||&&|[;&|\n()`]|\$\(/, $c;
}
exit 0;
