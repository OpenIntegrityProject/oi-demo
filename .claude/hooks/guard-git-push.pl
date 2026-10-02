#!/usr/bin/env perl
# PreToolUse hook (Bash): block git pushes that force or that target main
# or staging/*. Backs up the deny rules in .claude/settings.json, which only
# match fixed command shapes. Still a mistake-catcher, not a security
# boundary: branch protection and the signature verifier are the real guard.
#
# Reads the hook JSON on stdin. Exit 2 with a reason on stderr blocks the
# command; exit 0 allows it.
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

my $prefix_word = qr{^(?:\w+=\S*|-\S*|\d\S*
  |(?:\S*/)?(?:sudo|env|exec|command|builtin|nohup|nice|time|timeout|stdbuf|xargs|eval|(?:ba|z|da|k)?sh))$}x;

sub protected {
  my ($ref) = @_;
  $ref =~ s{^refs/heads/}{};
  return $ref eq 'main' || $ref =~ m{^staging/};
}

sub current_branch {
  my $branch = `git symbolic-ref --quiet --short HEAD 2>/dev/null` // '';
  chomp $branch;
  return $branch;
}

sub block {
  print STDERR "guard-git-push: blocked: $_[0]. Agents push only to claude/* "
    . "branches without force; a human merges with merge_pr.sh.\n";
  exit 2;
}

# Drop heredoc bodies (commit messages, file contents) unless a shell reads
# them, and neutralize substitution syntax inside single quotes, where it is
# literal text.
$command =~ s{^([^\n]*?<<-?\s*(['"]?)(\w+)\2[^\n]*\n)(.*?)^\s*\3\s*$}
  { my ($head, $body) = ($1, $4);
    $head =~ m{(?:^|[\s/])(?:ba|z|da|k)?sh\b} ? "$head$body" : "$head\n" }gmse;
$command =~ s{'[^']*'}{ (my $q = $&) =~ s/`|\$\(/ /g; $q }ge;

# Split into simple commands at shell separators, subshells and
# substitutions, then drop quotes so `sh -c 'git push ...'` is inspected too.
for my $segment (split /\|\||&&|[;&|\n()`]|\$\(/, $command) {
  (my $flat = $segment) =~ s/["'\\]/ /g;
  my @words = split ' ', $flat;

  # Find git (any path, e.g. /usr/bin/git) in command position: preceded
  # only by assignments, wrappers, their flags and numbers, or `sh -c`.
  # Text that merely mentions git push (echo, commit messages) is skipped.
  my $i = 0;
  $i++ while $i < @words && $words[$i] !~ m{(?:^|/)git$} && $words[$i] =~ $prefix_word;
  next unless $i < @words && $words[$i] =~ m{(?:^|/)git$};
  $i++;
  while ($i < @words && $words[$i] =~ /^-/) {
    $i += $git_opt_with_value{$words[$i]} ? 2 : 1;
  }
  next unless $i < @words && $words[$i] eq 'push';

  my @positional;
  for (my $j = $i + 1; $j < @words; $j++) {
    my $w = $words[$j];
    if ($w eq '--') { push @positional, @words[$j + 1 .. $#words]; last }
    if ($w =~ /^--(?:force|mirror|all|branches)/) { block("git push $w") }
    if ($w =~ /^-[^-]*f/)                         { block("git push with -f ($w)") }
    if ($push_opt_with_value{$w})                 { $j++; next }
    next if $w =~ /^-/;
    push @positional, $w;
  }

  my ($remote, @refspecs) = @positional;
  for my $spec (@refspecs) {
    block("force refspec $spec") if $spec =~ /^\+/;
    my $dst = $spec =~ /:/ ? (split /:/, $spec, 2)[1] : $spec;
    $dst = current_branch() if $dst eq 'HEAD' || $dst eq '@';
    block("push to protected branch ($spec)") if protected($dst);
  }
  # With no refspec, git pushes the current branch (default push.default)
  if (!@refspecs) {
    my $branch = current_branch();
    block("push from protected branch $branch") if protected($branch);
  }
}
exit 0;
