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
# Directory the command starts in; cd moves it (see check_segment)
my $cwd;
if (eval { require JSON::PP; 1 }) {
  my $data = eval { JSON::PP::decode_json($input) };
  if (ref $data eq 'HASH') {
    $command = $data->{tool_input}{command} // '';
    $cwd = $data->{cwd} if defined $data->{cwd} && -d $data->{cwd};
  }
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
  |(?:\S*/)?(?:sudo|env|exec|command|builtin|nohup|nice|timeout|stdbuf|xargs|eval
    |arch|xcrun|caffeinate|script|(?:ba|z|da|k|c|tc)?sh))$}x;
my $shell = qr{(?:^|[\s/])(?:ba|z|da|k|c|tc)?sh\b};
my $git_word = qr{(?:^|/)git$};
# Config keys that choose where, or what, git push sends
my $dest_key = qr{^(?:push\.\S+|remote\.(?:\S+\.(?:push|mirror)|pushdefault)
  |branch\.\S+\.(?:merge|remote|pushremote)|include(?:if)?\.\S+)$}xi;
# Placeholder for a command substitution whose output can't be known
my $unknown = '$__substitution__';
# Placeholder for a substitution that names the current branch. It is
# resolved when the push is checked, since an earlier checkout may move it.
my $current = "\x01";

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
sub config_all { split /\n/, in_dir($_[0], 'config', '--get-all', $_[1]) }

# Set once an earlier part of the command may change the current branch;
# the hook reads the repo before any of the command runs
my $state_changed;
# Set when an earlier checkout -b or switch -c names the new current branch:
# { dir => where it ran, name => the branch }
my $created;

sub branch_at {
  my ($dir) = @_;
  block("$state_changed, so the current branch can't be checked; push a literal claude/* name")
    if $state_changed;
  if ($created) {
    block("an earlier branch switch ran in another directory, so the current branch "
      . "can't be checked; push a literal claude/* name") if ($created->{dir} // '') ne ($dir // '');
    return $created->{name};
  }
  return current_branch($dir);
}

# The branch a checkout -b/-B or switch -c/-C creates, if the command has one
sub created_branch {
  my ($sub, @args) = @_;
  my ($flag, $stuck) = $sub eq 'checkout' ? (qr/^-\w*[bB]$|^--orphan$/, qr/^(?:-[bB]|--orphan=)(.+)$/)
    : $sub eq 'switch' ? (qr/^-\w*[cC]$|^--(?:create|force-create|orphan)$/,
      qr/^(?:-[cC]|--(?:create|force-create|orphan)=)(.+)$/)
    : return;
  for my $j (0 .. $#args) {
    return $args[$j + 1] if $args[$j] =~ $flag;
    return $1 if $args[$j] =~ $stuck;
  }
  return;
}

# True when a word names a git command rather than an alias
my %git_commands;
sub is_git_command {
  %git_commands = map { $_ => 1 } split /\n/, in_dir(undef, '--list-cmds=main,others')
    unless %git_commands;
  return $git_commands{$_[0]};
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

# True when a word, possibly a glob, could name merge_pr.sh
sub is_merge_pr {
  (my $base = $_[0]) =~ s{.*/}{};
  (my $re = quotemeta $base) =~ s/\\\*/.*/g;
  $re =~ s/\\\?/./g;
  return 'merge_pr.sh' =~ /^$re$/;
}

# Shell variables assigned earlier in the command: name => [values]
my %vars;
# Set when the command puts git config or a repo location in the environment
my $env_config;

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

# Check one refspec's destination
sub check_refspec {
  my ($dir, $spec, $from) = @_;
  for my $s (expand($spec)) {
    (my $shown = $s) =~ s/$current/\$(current branch)/g;
    $shown .= ", from $from" if $from;
    block("force refspec $shown") if $s =~ /^\+/;
    block("refspec : pushes every matching branch") if $s eq ':';
    my $dst = $s =~ /:/ ? (split /:/, $s, 2)[1] : $s;
    block("destination $shown can't be checked; use a literal branch name") if $dst =~ /\$/;
    $dst =~ s/$current/branch_at($dir)/ge;
    $dst = branch_at($dir) if $dst eq 'HEAD' || $dst eq '@';
    block("push to protected branch ($shown)") if protected($dst);
  }
}

sub check_push {
  my ($dir, $via_xargs, $override, @args) = @_;
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
  block("git push fed by xargs or find; destination can't be checked") if $via_xargs;
  block("$override changes where git push goes") if $override;

  my ($remote, @refspecs) = @positional;
  check_refspec($dir, $_) for @refspecs;

  # Without a refspec, the repo config and push.default pick the destination
  my $branch;
  if (!@refspecs) {
    $branch = branch_at($dir);
    ($remote) = ((map { config_all($dir, $_) } "branch.$branch.pushRemote",
      'remote.pushDefault', "branch.$branch.remote"), 'origin') unless defined $remote;
  }
  return unless defined $remote;
  my ($mirror) = config_all($dir, "remote.$remote.mirror");
  block("remote.$remote.mirror pushes every ref") if ($mirror // '') =~ /^(?:true|yes|on|1)$/i;
  # remote.<name>.push applies to a bare push, and also maps a refspec that
  # names only a source, so check it whenever it is set
  my @configured = config_all($dir, "remote.$remote.push");
  check_refspec($dir, $_, "remote.$remote.push") for @configured;

  # push.default=upstream also sends a refspec that names only a branch to
  # that branch's upstream
  my ($mode) = map { lc } config_all($dir, 'push.default'), 'simple';
  my $to_upstream = $mode eq 'upstream' || $mode eq 'tracking';
  if ($to_upstream && !@configured) {
    for my $s (map { expand($_) } grep { !/:/ && !/^\+?(?:HEAD|@)$/ } @refspecs) {
      (my $name = $s) =~ s{^\+?(?:refs/)?(?:heads/)?}{};
      block("push.default=$mode sends $name to its upstream, which an earlier part of the "
        . "command may change; push to an explicit claude/*:claude/* refspec")
        if $state_changed || $created;
      my ($up) = config_all($dir, "branch.$name.merge");
      block("push.default=$mode sends $name to its upstream $up") if protected($up // '');
    }
  }
  return if @refspecs || @configured;

  return if $mode eq 'nothing';
  block("push.default=matching pushes every branch the remote also has") if $mode eq 'matching';
  # A branch created in this command may track a protected one already
  block("push.default=$mode pushes to the upstream of $branch, which this command just "
    . "created, so it can't be checked; push a literal claude/* name")
    if $created && $to_upstream;
  my $dst = $branch;
  ($dst) = config_all($dir, "branch.$branch.merge") if $to_upstream;
  block("push from $branch goes to protected branch $dst") if protected($dst // '');
}

# Note git commands that change the current branch, and block ones that
# change the push config
sub check_state_change {
  my ($dir, $sub, @args) = @_;
  if ($sub eq 'config' && !grep { /^(?:--get\S*|--list|-l|get|list)$/ } @args) {
    my ($key) = grep { /$dest_key/ } @args;
    block("git config $key changes where git push goes") if defined $key;
  }
  block("git remote --mirror changes what git push sends")
    if $sub eq 'remote' && grep { /^--mirror/ } @args;
  my $name = created_branch($sub, @args);
  if (defined $name && $name !~ /\$/) {
    ($state_changed, $created) = (undef, { dir => $dir, name => $name });
    return;
  }
  ($state_changed, $created) = ("an earlier git $sub may change the branch", undef)
    if $sub =~ /^(?:switch|rebase)$/
    || ($sub eq 'checkout' && !grep { $_ eq '--' } @args)
    || ($sub eq 'worktree' && ($args[0] // '') !~ /^(?:list|prune)$/)
    || ($sub eq 'branch' && grep { /^(?:-[^-]*[mMut]|--(?:move|track|set-upstream))/ } @args)
    || ($sub eq 'symbolic-ref' && (grep { !/^-/ } @args) >= 2);
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

  # Config or a repo location in the environment (GIT_CONFIG_PARAMETERS,
  # GIT_CONFIG_COUNT, GIT_DIR, ...) can't be read here
  my ($env) = grep { /^(?:GIT_CONFIG\w*|GIT_DIR|GIT_WORK_TREE)=/ } @words;
  $env_config //= "setting $1" if defined $env && $env =~ /^(\w+)=/;

  # Skip to the command word, recording assignments and xargs on the way.
  # A word right after a flag may be that flag's value (sudo -iu user).
  # find runs what follows -exec; script takes a file before the command.
  my ($i, $via_xargs, $script_file) = (0, 0, 0);
  while ($i < @words && $words[$i] !~ $git_word && !is_merge_pr($words[$i])) {
    my $w = $words[$i];
    if ($w =~ m{(?:^|/)find$}) {
      $i++ while $i < @words && $words[$i] !~ /^-(?:exec|execdir|ok|okdir)$/;
      $via_xargs = 1;
    }
    elsif ($w =~ /^(\w+)=(.*)$/) { $vars{$1} = [$2] }
    elsif ($w =~ $prefix_word) {
      $via_xargs = 1 if $w =~ m{(?:^|/)xargs$};
      $script_file = 1 if $w =~ m{(?:^|/)script$};
    }
    elsif ($i > 0 && $words[$i - 1] =~ /^-/ && $words[$i - 1] !~ /^-\w*c$/) { }
    elsif ($script_file) { $script_file = 0 }
    else  { last }
    $i++;
  }
  return if $i >= @words;

  # cd moves where the current branch and config are read from
  if ($words[$i] =~ /^(?:cd|pushd|popd)$/) {
    my $to = $words[$i] eq 'popd' ? undef : $words[$i + 1] // $ENV{HOME};
    $to =~ s{^~(?=/|$)}{$ENV{HOME}} if defined $to;
    $to = "$cwd/$to" if defined $to && defined $cwd && $to !~ m{^/};
    if (defined $to && $to !~ /\$|^-/ && -d $to) { $cwd = $to }
    else { $state_changed //= "an earlier $words[$i] moves to a directory that can't be checked" }
    return;
  }

  my @cmd = expand($words[$i]);
  block("merge_pr.sh is the human's step") if grep { is_merge_pr($_) } @cmd;
  # An unresolved command word could be git
  return unless grep { /$git_word/ || /\$/ } @cmd;
  $i++;

  # $hidden: config the hook can't read, which could define an alias
  my ($dir, $override, $hidden, %cli_alias) = ($cwd, $env_config, $env_config);
  while ($i < @words && $words[$i] =~ /^-/) {
    my ($opt, $val) = ($words[$i], $words[$i + 1] // '');
    if ($opt eq '-C') {
      $dir = (defined $dir && $val !~ m{^/}) ? "$dir/$val" : $val;
    }
    if ($opt eq '-c' && $val =~ /^alias\.([^=]+)=(.*)$/i) {
      $cli_alias{lc $1} = $2;    # git lowercases config keys
    }
    my ($key) = $opt eq '-c' ? $val =~ /^([^=]*)/ : ();
    $override //= "git -c $key" if defined $key && $key =~ $dest_key;
    $override //= "git $opt" if $opt =~ /^--(?:config-env|git-dir|work-tree)/;
    $hidden //= "git $opt" if $opt =~ /^--config-env/;
    $hidden //= "git -c $key" if defined $key && $key =~ /^include/i;
    $i += $git_opt_with_value{$opt} ? 2 : 1;
  }
  return unless $i < @words;

  my ($sub, @args) = @words[$i .. $#words];
  for my $s (expand($sub)) {
    # An unresolved subcommand could be push, or could change the branch
    if ($push_like{$s} || $s =~ /\$/) {
      check_push($dir, $via_xargs, $override, @args);
      $state_changed //= "an earlier git $s may change the branch" if $s =~ /\$/;
      next;
    }
    check_state_change($dir, $s, @args);
    my $alias = $cli_alias{lc $s} // in_dir($dir, 'config', '--get', "alias.$s");
    if ($alias eq '') {
      block("$hidden could make git $s an alias for push, and the hook can't read it")
        if $hidden && !is_git_command($s);
      next;
    }
    if ($alias =~ /^!/) {
      block("git alias $s runs a shell command that pushes") if $alias =~ /\bpush\b/;
      $state_changed //= "git alias $s runs a shell command"
        if $alias =~ /\b(?:checkout|switch|rebase|worktree|branch|symbolic-ref|config|cd)\b/;
      next;
    }
    my ($alias_sub, @alias_args) = split ' ', $alias;
    if ($push_like{$alias_sub}) { check_push($dir, $via_xargs, $override, @alias_args, @args) }
    else                        { check_state_change($dir, $alias_sub, @alias_args, @args) }
  }
}

# True when quoted text in a command goes to a shell as a script
# (sh -c '...', eval "...") rather than being data such as a message
sub is_script {
  (my $cmd = $_[0]) =~ s/["'\\]//g;
  return ($cmd =~ $shell || $cmd =~ /(?:^|\s)eval\s/) ? 1 : 0;
}

# Read the command the way the shell would, far enough to tell code from
# text: drop comments, and heredoc bodies unless a shell reads them; join
# backslash-newline continuations; decode $'...' quoting; and blank out
# separators, newlines and substitution syntax in quoted text, so a commit
# message or PR body can't read as commands. Quoted text that is a script
# for a shell stays as written, to be checked as code.
sub normalize {
  my ($in) = @_;
  my ($out, $p, $line_start, @heredocs) = ('', 0, 0);
  # Levels of nesting: code (the top, $(...), `...`) or quoted text.
  # Each code level keeps the text of its current simple command.
  my @stack = ({ code => 1, close => '', depth => 0, cmd => '' });
  while ($p < length $in) {
    my ($c, $two, $lv) = (substr($in, $p, 1), substr($in, $p, 2), $stack[-1]);

    if (!$lv->{code}) {
      my $owner = $stack[-2];
      if ($c eq $lv->{close}) { pop @stack }
      elsif ($lv->{close} eq '"' && $c eq '\\') {
        my $esc = substr($in, $p + 1, 1);
        $out .= "\\$esc" unless $esc eq "\n";
        $owner->{cmd} .= "\\$esc";
        $p += 2;
        next;
      }
      elsif ($lv->{close} eq '"' && ($two eq '$(' || $c eq '`')) {
        push @stack, { code => 1, close => $c eq '`' ? '`' : ')', depth => 0, cmd => '' };
        $out .= $c eq '`' ? $c : $two;
        $p += length($c eq '`' ? $c : $two);
        next;
      }
      elsif (!$lv->{script} && $c =~ /[;&|()\n`]/) { $c = ' ' }
      $owner->{cmd} .= $c;
      $out .= $c;
      $p++;
      next;
    }

    if ($c eq '\\') {
      my $esc = substr($in, $p + 1, 1);
      $out .= "\\$esc" unless $esc eq "\n";
      $lv->{cmd} .= "\\$esc";
      $p += 2;
      next;
    }
    if ($lv->{close} eq ')' && $c eq '(') { $lv->{depth}++ }
    if (($lv->{close} eq ')' && $c eq ')' && !$lv->{depth}--) || ($lv->{close} eq '`' && $c eq '`')) {
      pop @stack;
      $out .= $c;
      $p++;
      next;
    }
    # A comment runs to the end of the line
    if ($c eq '#' && ($p == 0 || substr($in, $p - 1, 1) =~ /[\s;&|()<>]/)) {
      my $nl = index($in, "\n", $p);
      $p = $nl < 0 ? length $in : $nl;
      next;
    }
    if (substr($in, $p) =~ /^\$'((?:[^'\\]|\\.)*)'/s) {
      my ($s, $all) = ($1, $&);
      $s =~ s{\\x([0-9a-fA-F]{1,2})|\\([0-7]{1,3})|\\(.)}
        { defined $1 ? chr(hex $1) : defined $2 ? chr(oct $2) : $3 eq 'n' ? "\n" : $3 eq 't' ? "\t" : $3 }ge;
      $s =~ s/['"\\]//g;
      $s =~ s/[;&|()\n`]/ /g unless is_script($lv->{cmd});
      $out .= $s;
      $lv->{cmd} .= $s;
      $p += length $all;
      next;
    }
    if ($c eq "'" || $c eq '"') {
      push @stack, { code => 0, close => $c, script => is_script($lv->{cmd}) };
    }
    elsif ($two eq '$(' || $c eq '`') {
      push @stack, { code => 1, close => $c eq '`' ? '`' : ')', depth => 0, cmd => '' };
      if ($two eq '$(') { $out .= $two; $p += 2; next }
    }
    elsif (substr($in, $p) =~ /^<<-?\s*(?:(['"])(\w+)\1|\\?(\w+))/) {
      push @heredocs, $2 // $3;
      $out .= $&;
      $lv->{cmd} .= $&;
      $p += length $&;
      next;
    }
    elsif ($c eq "\n") {
      # Heredoc bodies start on the next line. A body counts only when its
      # terminator is found, so a stray << can't hide the lines after it.
      my $line = substr($in, $line_start, $p - $line_start);
      $p++;
      if ($line !~ $shell) {
        for my $end (@heredocs) {
          $p += length $& if substr($in, $p) =~ /\A.*?^[ \t]*\Q$end\E[ \t]*(?:\n|\z)/ms;
        }
      }
      @heredocs = ();
      $line_start = $p;
      $lv->{cmd} = '';
      $out .= "\n";
      next;
    }
    $lv->{cmd} = $c =~ /[;&|()]/ ? '' : $lv->{cmd} . $c;
    $out .= $c;
    $p++;
  }
  return $out;
}

# Read here-strings as input to whatever precedes them (bash <<< "...")
$command =~ s/<<</ /g;
$command = normalize($command);

# Pull out command substitutions, innermost first: each is checked as a
# command of its own, and stands in its outer command as an unknown value,
# so a destination like HEAD:$(echo main) is blocked as unresolvable. The
# usual ways of naming the current branch are resolved instead. Plain
# parentheses inside a substitution, $( (echo main) ), are kept with it.
my @commands;
for (1 .. 20) {
  last unless $command =~ s{\$\(((?:[^()`\$]++|\$(?!\()|\((?1)\))*)\)|`([^`]*)`}{
    my $inner = $1 // $2;
    push @commands, $inner;
    $inner =~ /^\s*git\s+(?:branch\s+--show-current|rev-parse\s+--abbrev-ref\s+HEAD|symbolic-ref\s+(?:--quiet\s+)?--short\s+HEAD)\s*$/
      ? $current : $unknown }ge;
}
push @commands, $command;

# Split into simple commands at shell separators and subshells
for my $c (@commands) {
  check_segment($_) for split /\|\||&&|[;&|\n()`]|\$\(/, $c;
}
exit 0;
