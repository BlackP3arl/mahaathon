-- mahathon26 judging — Supabase schema
-- Tables are closed to the API; judges read and write only through the PIN-checked functions below.

create extension if not exists pgcrypto with schema extensions;

create table public.judges(
  seat smallint primary key check (seat between 0 and 3),  -- 0 = organiser (results only)
  name text not null default '',
  pin_hash text not null,
  failed smallint not null default 0,
  locked_until timestamptz
);

create table public.scores(
  seat smallint not null references public.judges(seat) check (seat between 1 and 3),
  team smallint not null check (team between 1 and 10),
  wow smallint not null default 0 check (wow between 0 and 5),
  func smallint not null default 0 check (func between 0 and 5),
  pres smallint not null default 0 check (pres between 0 and 5),
  joint boolean not null default false,
  note text not null default '' check (length(note) <= 1000),
  updated_at timestamptz not null default now(),
  primary key (seat, team)
);

alter table public.judges enable row level security;
alter table public.scores enable row level security;
revoke all on public.judges, public.scores from anon, authenticated;

-- Returns null when the PIN is right, otherwise an error message.
-- 5 wrong PINs lock the seat for 5 minutes.
create function public._check_pin(p_seat int, p_pin text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare j public.judges;
begin
  select * into j from public.judges where seat = p_seat for update;
  if not found then return 'Unknown seat'; end if;
  if j.locked_until is not null and j.locked_until > now() then
    return 'Too many wrong PINs. Try again in a few minutes.';
  end if;
  if j.pin_hash <> extensions.crypt(coalesce(p_pin,''), j.pin_hash) then
    if j.failed + 1 >= 5 then
      update public.judges set failed = 0, locked_until = now() + interval '5 minutes' where seat = p_seat;
      return 'Too many wrong PINs. Try again in a few minutes.';
    end if;
    update public.judges set failed = failed + 1 where seat = p_seat;
    return 'Wrong PIN';
  end if;
  if j.failed > 0 or j.locked_until is not null then update public.judges set failed = 0, locked_until = null where seat = p_seat; end if;
  return null;
end $$;
revoke all on function public._check_pin(int, text) from public, anon, authenticated;

create function public.judge_login(p_seat int, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
declare e text := public._check_pin(p_seat, p_pin);
begin
  if e is not null then return json_build_object('error', e); end if;
  return json_build_object('seat', p_seat, 'name', (select name from public.judges where seat = p_seat),
    'scores', coalesce((select json_agg(s order by team) from (select team, wow, func, pres, joint, note, updated_at from public.scores where seat = p_seat) s), '[]'::json));
end $$;

create function public.set_name(p_seat int, p_pin text, p_name text)
returns json language plpgsql security definer set search_path = public as $$
declare e text := public._check_pin(p_seat, p_pin);
begin
  if e is not null then return json_build_object('error', e); end if;
  if p_seat between 1 and 3 then update public.judges set name = left(trim(coalesce(p_name,'')), 40) where seat = p_seat; end if;
  return json_build_object('ok', true);
end $$;

create function public.save_score(p_seat int, p_pin text, p_team int, p_wow int, p_func int, p_pres int, p_joint boolean, p_note text)
returns json language plpgsql security definer set search_path = public as $$
declare e text; t timestamptz := now();
begin
  if p_seat is null or p_seat not between 1 and 3 then return json_build_object('error','Only judges can score'); end if;
  e := public._check_pin(p_seat, p_pin);
  if e is not null then return json_build_object('error', e); end if;
  if p_team is null or p_team not between 1 and 10 then return json_build_object('error','Unknown team'); end if;
  insert into public.scores(seat, team, wow, func, pres, joint, note, updated_at)
  values (p_seat, p_team, least(greatest(coalesce(p_wow,0),0),5), least(greatest(coalesce(p_func,0),0),5), least(greatest(coalesce(p_pres,0),0),5),
          coalesce(p_joint,false), left(coalesce(p_note,''),1000), t)
  on conflict (seat, team) do update set wow = excluded.wow, func = excluded.func, pres = excluded.pres,
    joint = excluded.joint, note = excluded.note, updated_at = t;
  return json_build_object('ok', true, 'at', t);
end $$;

-- Results for any judge or the organiser; notes only to their author and the organiser.
create function public.get_board(p_seat int, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
declare e text := public._check_pin(p_seat, p_pin);
begin
  if e is not null then return json_build_object('error', e); end if;
  return json_build_object(
    'judges', (select json_agg(json_build_object('seat', seat, 'name', name) order by seat) from public.judges where seat between 1 and 3),
    'scores', coalesce((select json_agg(json_build_object('seat', seat, 'team', team, 'wow', wow, 'func', func, 'pres', pres, 'joint', joint,
                 'note', case when p_seat = 0 or p_seat = seat then note else null end)) from public.scores), '[]'::json));
end $$;

revoke all on function public.judge_login(int,text), public.set_name(int,text,text),
  public.save_score(int,text,int,int,int,int,boolean,text), public.get_board(int,text) from public;
grant execute on function public.judge_login(int,text), public.set_name(int,text,text),
  public.save_score(int,text,int,int,int,int,boolean,text), public.get_board(int,text) to anon, authenticated;

-- Create the four seats with random 6-digit PINs and show them once.
-- Hand the PINs out privately; only bcrypt hashes are stored.
with p as (
  select s as seat, lpad((floor(random()*1000000))::int::text, 6, '0') as pin from generate_series(0,3) s
), ins as (
  insert into public.judges(seat, name, pin_hash)
  select seat, case when seat = 0 then 'Organiser' else '' end, extensions.crypt(pin, extensions.gen_salt('bf')) from p
  returning seat
)
select p.seat, p.pin from p join ins using (seat) order by seat;

-- To change one PIN later:
-- update public.judges set pin_hash = extensions.crypt('123456', extensions.gen_salt('bf')), failed = 0, locked_until = null where seat = 1;

-- ---------------------------------------------------------------
-- Rounds and "Clear all scores" (organiser only)
-- Clearing archives every score, empties the score table and starts a new round.
-- Saves from a screen still on the old round are refused, so test scores can't come back.
create table public.settings(id smallint primary key default 1 check (id = 1), round int not null default 1, cleared_at timestamptz);
insert into public.settings(id) values (1);
alter table public.settings enable row level security;
revoke all on public.settings from anon, authenticated;

create table public.scores_archive(
  round int not null, seat smallint not null, team smallint not null,
  wow smallint, func smallint, pres smallint, joint boolean, note text,
  updated_at timestamptz, archived_at timestamptz not null default now()
);
alter table public.scores_archive enable row level security;
revoke all on public.scores_archive from anon, authenticated;

create or replace function public.judge_login(p_seat int, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
declare e text := public._check_pin(p_seat, p_pin);
begin
  if e is not null then return json_build_object('error', e); end if;
  return json_build_object('seat', p_seat, 'name', (select name from public.judges where seat = p_seat),
    'round', (select round from public.settings where id = 1),
    'scores', coalesce((select json_agg(s order by team) from (select team, wow, func, pres, joint, note, updated_at from public.scores where seat = p_seat) s), '[]'::json));
end $$;

-- The original save_score now refuses, so an out-of-date page can't write.
create or replace function public.save_score(p_seat int, p_pin text, p_team int, p_wow int, p_func int, p_pres int, p_joint boolean, p_note text)
returns json language plpgsql security definer set search_path = public as $$
begin
  return json_build_object('error','The judging app was updated. Reload the page and sign in again.');
end $$;

create or replace function public.save_score_v2(p_seat int, p_pin text, p_round int, p_team int, p_wow int, p_func int, p_pres int, p_joint boolean, p_note text)
returns json language plpgsql security definer set search_path = public as $$
declare e text; t timestamptz := now(); cur int;
begin
  if p_seat is null or p_seat not between 1 and 3 then return json_build_object('error','Only judges can score'); end if;
  e := public._check_pin(p_seat, p_pin);
  if e is not null then return json_build_object('error', e); end if;
  select round into cur from public.settings where id = 1;
  if p_round is distinct from cur then return json_build_object('reset', true, 'round', cur); end if;
  if p_team is null or p_team not between 1 and 10 then return json_build_object('error','Unknown team'); end if;
  insert into public.scores(seat, team, wow, func, pres, joint, note, updated_at)
  values (p_seat, p_team, least(greatest(coalesce(p_wow,0),0),5), least(greatest(coalesce(p_func,0),0),5), least(greatest(coalesce(p_pres,0),0),5),
          coalesce(p_joint,false), left(coalesce(p_note,''),1000), t)
  on conflict (seat, team) do update set wow = excluded.wow, func = excluded.func, pres = excluded.pres,
    joint = excluded.joint, note = excluded.note, updated_at = t;
  return json_build_object('ok', true, 'at', t);
end $$;

create or replace function public.clear_scores(p_seat int, p_pin text, p_confirm text, p_reset_names boolean)
returns json language plpgsql security definer set search_path = public as $$
declare e text; n int; cur int;
begin
  if p_seat is distinct from 0 then return json_build_object('error','Only the organiser can clear scores'); end if;
  e := public._check_pin(0, p_pin);
  if e is not null then return json_build_object('error', e); end if;
  if p_confirm is distinct from 'CLEAR' then return json_build_object('error','Type CLEAR to confirm'); end if;
  select round into cur from public.settings where id = 1 for update;
  insert into public.scores_archive(round, seat, team, wow, func, pres, joint, note, updated_at)
    select cur, seat, team, wow, func, pres, joint, note, updated_at from public.scores;
  get diagnostics n = row_count;
  delete from public.scores where true;
  if coalesce(p_reset_names, false) then update public.judges set name = '' where seat between 1 and 3; end if;
  update public.settings set round = cur + 1, cleared_at = now() where id = 1;
  return json_build_object('ok', true, 'archived', n, 'round', cur + 1);
end $$;

create or replace function public.get_board(p_seat int, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
declare e text := public._check_pin(p_seat, p_pin);
begin
  if e is not null then return json_build_object('error', e); end if;
  return json_build_object(
    'round', (select round from public.settings where id = 1),
    'cleared_at', (select cleared_at from public.settings where id = 1),
    'judges', (select json_agg(json_build_object('seat', seat, 'name', name) order by seat) from public.judges where seat between 1 and 3),
    'scores', coalesce((select json_agg(json_build_object('seat', seat, 'team', team, 'wow', wow, 'func', func, 'pres', pres, 'joint', joint,
                 'note', case when p_seat = 0 or p_seat = seat then note else null end)) from public.scores), '[]'::json));
end $$;

revoke all on function public.save_score_v2(int,text,int,int,int,int,int,boolean,text), public.clear_scores(int,text,text,boolean) from public;
grant execute on function public.save_score_v2(int,text,int,int,int,int,int,boolean,text), public.clear_scores(int,text,text,boolean) to anon, authenticated;

-- To restore archived scores from a round (example: round 1), run as admin:
-- insert into public.scores(seat, team, wow, func, pres, joint, note, updated_at)
--   select seat, team, wow, func, pres, joint, note, updated_at from public.scores_archive where round = 1
--   on conflict (seat, team) do nothing;
