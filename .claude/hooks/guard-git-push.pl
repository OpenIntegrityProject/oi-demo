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
# Wrapper options that take a separate value (sudo -u user, nice -n 5, ...)
my %wrapper_opt_with_value = map { $_ => 1 } qw(-u -g -h -p -s -n -k -C -D -U -T -r -t);

# Words that may come before the real command: assignments, wrappers and
# their flags or numbers, shells (sh -c, bash <<<), and shell keywords.
my $prefix_word = qr{^(?:\w+=\S*|-\S*|\d\S*|!|\{|\}
  |if|then|else|elif|do|while|until|time
  |(?:\S*/)?(?:sudo|env|exec|command|builtin|nohup|nice|timeout|stdbuf|xargs|eval|(?:ba|z|da|k)?sh))$}x;
my $shell = qr{(?:^|[\s/])(?:ba|z|da|k)?sh\b};

sub block {
  print STDERR "guard-git-push: blocked: $_[0]. Agents push only to literal "
    . "claude/* branches without force; a human merges with merge_pr.sh.\n";
  exit 2;
}

sub in_dir {
  my ($dir, @cmd) = @_;
  my @c = ('git', (defined $dir ? ('-C', $dir) : ()), @cmd);
  open(my $fh, '-|', @c) or return '';
  my $out = do { local $/; <$fh> } // '';
  close $fh;
  chomp $out;
  return $out;
}

sub current_branch {
  my ($dir) = @_;
  open(my $saved, '>&', \*STDERR);
  open(STDERR, '>', '/dev/null');
  my $branch = in_dir($dir, qw(symbolic-ref --quiet --short HEAD));
  open(STDERR, '>&', $saved);
  return $branch;
}

sub alias_of {
  my ($dir, $name) = @_;
  return in_dir($dir, 'config', '--get', "alias.$name");
}

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

# Shell variables assigned earlier in the command: name => [values]
my %vars;
sub expand {
  my ($word) = @_;
  my @out = ($word);
  while (grep { /\$\{?(\w+)\}?/ } @out) {
    my @next;
    for my $w (@out) {
      if ($w =~ /\$\{?(\w+)\}?/ && $vars{$1}) {
        my $name = $1;
        push @next, map { (my $x = $w) =~ s/\$\{?$name\}?/$_/; $x } @{ $vars{$name} };
      } elsif ($w =~ /\$/) {
        return ($w);    # unresolved: caller blocks
      } else {
        push @next, $w;
      }
    }
    @out = @next;
  }
  return @out;
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

# Normalize: join backslash-newline continuations, read here-strings as
# input to whatever precedes them, drop heredoc bodies unless a shell reads
# them, and neutralize substitution syntax inside single quotes.
$command =~ s/\\\n//g;
$command =~ s/<<</ /g;
$command =~ s{^([^\n]*?<<-?\s*(['"]?)(\w+)\2[^\n]*\n)(.*?)^\s*\3\s*$}
  { my ($head, $body) = ($1, $4); $head =~ $shell ? "$head$body" : "$head\n" }gmse;
$command =~ s{'[^']*'}{ (my $q = $&) =~ s/`|\$\(/ /g; $q }ge;

# Split into simple commands at shell separators, subshells and
# substitutions, then remove quoting so `sh -c 'git push ...'`, "m"ain and
# ma\in read as the shell would see them.
for my $segment (split /\|\||&&|[;&|\n()`]|\$\(/, $command) {
  (my $flat = $segment) =~ s/["'\\]//g;
  my @words = split ' ', $flat;

  # for NAME in a b c  -> NAME may be any of a b c
  if (@words >= 3 && $words[0] eq 'for' && $words[2] eq 'in') {
    push @{ $vars{$words[1]} }, @words[3 .. $#words];
    next;
  }

  # Skip to the command word, recording assignments and xargs on the way.
  my ($i, $via_xargs) = (0, 0);
  while ($i < @words && $words[$i] =~ $prefix_word && $words[$i] !~ m{(?:^|/)git$}) {
    if ($words[$i] =~ /^(\w+)=(.*)$/) { $vars{$1} = [$2] }
    $via_xargs = 1 if $words[$i] =~ m{(?:^|/)xargs$};
    $i += ($wrapper_opt_with_value{$words[$i]} && $i > 0 && $words[$i - 1] !~ $shell) ? 2 : 1;
  }
  next if $i >= @words;

  block("merge_pr.sh is the human's step") if $words[$i] =~ m{(?:^|/)merge_pr\.sh$};
  next unless $words[$i] =~ m{(?:^|/)git$};
  $i++;

  my $dir;
  while ($i < @words && $words[$i] =~ /^-/) {
    if ($words[$i] eq '-C' && $i + 1 < @words) {
      my $d = $words[$i + 1];
      $dir = (defined $dir && $d !~ m{^/}) ? "$dir/$d" : $d;
    }
    $i += $git_opt_with_value{$words[$i]} ? 2 : 1;
  }
  next unless $i < @words;

  my ($sub, @args) = @words[$i .. $#words];
  if ($sub ne 'push') {
    my $alias = alias_of($dir, $sub);
    next if $alias eq '';
    block("git alias $sub runs a shell command that pushes") if $alias =~ /^!.*\bpush\b/;
    next unless $alias =~ /^\s*push\b\s*(.*)$/;
    unshift @args, split ' ', $1;
  }
  check_push($dir, $via_xargs, @args);
}
exit 0;
