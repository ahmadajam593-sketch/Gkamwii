-- =====================================================================
-- HAKAWI (حكاوي) — Supabase schema, security rules and server functions
-- Run this whole file once in: Supabase Dashboard -> SQL Editor -> New query -> Run.
-- It is safe to run again (idempotent).
-- =====================================================================

-- ---------- 1. TABLES ----------

create table if not exists public.store_items (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  kind text not null check (kind in ('theme','frame','category','feature')),
  price integer not null default 0 check (price >= 0),
  payload jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  sort integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  is_exclusive boolean not null default false,
  unlock_item uuid references public.store_items(id) on delete set null,
  sort integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  role text not null default 'user' check (role in ('user','admin')),
  points integer not null default 0 check (points >= 0),
  banned boolean not null default false,
  theme_item uuid references public.store_items(id) on delete set null,
  frame_item uuid references public.store_items(id) on delete set null,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists public.stories (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  narrator text,
  description text,
  duration_sec integer not null default 0,
  media_type text not null default 'audio' check (media_type in ('audio','video','link')),
  media_url text,
  cover_url text,
  category_id uuid references public.categories(id) on delete set null,
  status text not null default 'published' check (status in ('published','hidden')),
  is_featured boolean not null default false,
  allow_repeat boolean not null default false,
  reward_eligible boolean not null default true,
  views integer not null default 0,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists stories_created_idx on public.stories (created_at desc);
create index if not exists stories_views_idx on public.stories (views desc);

create table if not exists public.favorites (
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  story_id uuid not null references public.stories(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, story_id)
);

create table if not exists public.playback_progress (
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  story_id uuid not null references public.stories(id) on delete cascade,
  position_ms bigint not null default 0,
  updated_at timestamptz not null default now(),
  primary key (user_id, story_id)
);

create table if not exists public.story_views (
  user_id uuid not null references public.profiles(id) on delete cascade,
  story_id uuid not null references public.stories(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, story_id)
);

create table if not exists public.watch_progress (
  user_id uuid not null references public.profiles(id) on delete cascade,
  story_id uuid not null references public.stories(id) on delete cascade,
  seconds_watched integer not null default 0,
  last_report_at timestamptz,
  awarded_count integer not null default 0,
  last_awarded_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key (user_id, story_id)
);

create table if not exists public.points_ledger (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  amount integer not null,
  kind text not null check (kind in ('watch','purchase','admin_grant','admin_deduct')),
  note text,
  ref_id uuid,
  created_at timestamptz not null default now()
);
create index if not exists ledger_user_idx on public.points_ledger (user_id, created_at desc);

create table if not exists public.purchases (
  user_id uuid not null references public.profiles(id) on delete cascade,
  item_id uuid not null references public.store_items(id) on delete cascade,
  price_paid integer not null default 0,
  created_at timestamptz not null default now(),
  primary key (user_id, item_id)
);

create table if not exists public.ads (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  media_type text not null default 'image' check (media_type in ('video','image')),
  media_url text,
  image_url text,
  link_url text,
  duration_sec integer not null default 10,
  skippable boolean not null default true,
  skip_after_sec integer not null default 5,
  active boolean not null default true,
  impressions integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.app_settings (
  key text primary key,
  value jsonb not null
);

create table if not exists public.installs (
  device_id uuid primary key,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now()
);

-- ---------- 2. HELPER FUNCTIONS (used by security policies) ----------

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.is_banned() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select banned from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.owns_item(p_item uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.purchases where user_id = auth.uid() and item_id = p_item);
$$;

create or replace function public.can_view_category(p_cat uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select case
    when p_cat is null then true
    else coalesce((
      select (not c.is_exclusive)
             or public.is_admin()
             or (c.unlock_item is not null and public.owns_item(c.unlock_item))
      from public.categories c where c.id = p_cat
    ), true)
  end;
$$;

-- ---------- 3. NEW USER -> PROFILE ----------
-- The role is ALWAYS 'user' here. Admin is granted only by running supabase/make_admin.sql.

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id, new.email,
    coalesce(nullif(new.raw_user_meta_data->>'display_name', ''), split_part(new.email, '@', 1))
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- 4. ROW LEVEL SECURITY ----------

alter table public.store_items enable row level security;
alter table public.categories enable row level security;
alter table public.profiles enable row level security;
alter table public.stories enable row level security;
alter table public.favorites enable row level security;
alter table public.playback_progress enable row level security;
alter table public.story_views enable row level security;
alter table public.watch_progress enable row level security;
alter table public.points_ledger enable row level security;
alter table public.purchases enable row level security;
alter table public.ads enable row level security;
alter table public.app_settings enable row level security;
alter table public.installs enable row level security;

-- profiles: users read their own row; admin reads all. Users may change ONLY display_name.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
revoke insert, delete on public.profiles from anon, authenticated;
revoke update on public.profiles from anon, authenticated;
grant update (display_name) on public.profiles to authenticated;

-- stories: published stories (that the user may see) for everyone signed in; admin sees and edits all.
drop policy if exists stories_select on public.stories;
create policy stories_select on public.stories for select to authenticated
  using (public.is_admin() or (status = 'published' and not public.is_banned() and public.can_view_category(category_id)));
drop policy if exists stories_admin_write on public.stories;
create policy stories_admin_write on public.stories for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- categories
drop policy if exists categories_select on public.categories;
create policy categories_select on public.categories for select to authenticated using (true);
drop policy if exists categories_admin_write on public.categories;
create policy categories_admin_write on public.categories for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- store items
drop policy if exists store_select on public.store_items;
create policy store_select on public.store_items for select to authenticated
  using (active or public.is_admin());
drop policy if exists store_admin_write on public.store_items;
create policy store_admin_write on public.store_items for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- favorites + playback progress: strictly the owner's own rows
drop policy if exists favorites_own on public.favorites;
create policy favorites_own on public.favorites for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists progress_own on public.playback_progress;
create policy progress_own on public.playback_progress for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- points ledger and purchases: read-only for users (written only by the server functions below)
drop policy if exists ledger_select on public.points_ledger;
create policy ledger_select on public.points_ledger for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
drop policy if exists purchases_select on public.purchases;
create policy purchases_select on public.purchases for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
revoke insert, update, delete on public.points_ledger from anon, authenticated;
revoke insert, update, delete on public.purchases from anon, authenticated;
revoke all on public.watch_progress from anon, authenticated;
revoke all on public.story_views from anon, authenticated;
revoke all on public.installs from anon, authenticated;

-- ads: active ads for everyone signed in; admin manages
drop policy if exists ads_select on public.ads;
create policy ads_select on public.ads for select to authenticated
  using (active or public.is_admin());
drop policy if exists ads_admin_write on public.ads;
create policy ads_admin_write on public.ads for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- settings
drop policy if exists settings_select on public.app_settings;
create policy settings_select on public.app_settings for select to authenticated using (true);
drop policy if exists settings_admin_write on public.app_settings;
create policy settings_admin_write on public.app_settings for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------- 5. SERVER FUNCTIONS (the only way to touch points / purchases / views) ----------

create or replace function public.touch_last_seen() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  update public.profiles set last_seen_at = now() where id = auth.uid();
end $$;

create or replace function public.register_install(p_device uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into public.installs (device_id) values (p_device)
  on conflict (device_id) do update set last_seen = now();
end $$;

create or replace function public.register_view(p_story uuid) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); n integer;
begin
  if uid is null then return; end if;
  insert into public.story_views (user_id, story_id) values (uid, p_story) on conflict do nothing;
  get diagnostics n = row_count;
  if n > 0 then
    update public.stories set views = views + 1 where id = p_story;
  end if;
end $$;

create or replace function public.register_ad_view(p_ad uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  update public.ads set impressions = impressions + 1 where id = p_ad;
end $$;

-- Points for watching. The app reports REAL playing seconds; the server:
--  * caps what can be added by the wall-clock time since the previous report (seeking/skipping earns nothing),
--  * requires watched seconds >= min_watch_ratio * story duration,
--  * awards once per story unless the admin enabled allow_repeat,
--  * enforces a daily cap.
create or replace function public.report_watch(p_story uuid, p_seconds integer) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  s public.stories%rowtype;
  cfg jsonb;
  min_dur integer; pts integer; ratio numeric; daily_cap integer;
  wp public.watch_progress%rowtype;
  allowed integer; add_sec integer; required integer;
  today_total integer; new_balance integer;
  awarded boolean := false; capped boolean := false;
begin
  if uid is null then raise exception 'not authenticated'; end if;
  if public.is_banned() then raise exception 'banned'; end if;

  select * into s from public.stories where id = p_story and status = 'published';
  if not found then raise exception 'story not found'; end if;

  select value into cfg from public.app_settings where key = 'reward';
  min_dur   := coalesce((cfg->>'min_duration_sec')::integer, 600);
  pts       := coalesce((cfg->>'points')::integer, 5);
  ratio     := coalesce((cfg->>'min_watch_ratio')::numeric, 0.9);
  daily_cap := coalesce((cfg->>'daily_cap')::integer, 50);

  if (not s.reward_eligible) or s.duration_sec < min_dur or s.media_type = 'link' then
    return jsonb_build_object('eligible', false);
  end if;

  insert into public.watch_progress (user_id, story_id) values (uid, p_story) on conflict do nothing;
  select * into wp from public.watch_progress where user_id = uid and story_id = p_story for update;

  if wp.awarded_count > 0 and not s.allow_repeat then
    return jsonb_build_object('eligible', true, 'already_awarded', true);
  end if;

  if wp.last_report_at is null then
    allowed := 30;
  else
    allowed := least(60, floor(extract(epoch from (now() - wp.last_report_at)))::integer + 3);
  end if;
  add_sec  := greatest(0, least(coalesce(p_seconds, 0), allowed));
  required := ceil(s.duration_sec * ratio)::integer;

  update public.watch_progress
     set seconds_watched = seconds_watched + add_sec, last_report_at = now(), updated_at = now()
   where user_id = uid and story_id = p_story
   returning * into wp;

  if wp.seconds_watched >= required then
    select coalesce(sum(amount), 0) into today_total from public.points_ledger
     where user_id = uid and kind = 'watch' and created_at >= date_trunc('day', now());
    if today_total + pts > daily_cap then
      capped := true;
    else
      update public.profiles set points = points + pts where id = uid returning points into new_balance;
      insert into public.points_ledger (user_id, amount, kind, note, ref_id)
        values (uid, pts, 'watch', s.title, s.id);
      update public.watch_progress
         set awarded_count = awarded_count + 1, seconds_watched = 0, last_awarded_at = now()
       where user_id = uid and story_id = p_story;
      awarded := true;
    end if;
  end if;

  return jsonb_build_object(
    'eligible', true, 'awarded', awarded, 'capped', capped, 'points_added', case when awarded then pts else 0 end,
    'watched', wp.seconds_watched, 'required', required, 'balance', new_balance
  );
end $$;

create or replace function public.purchase_item(p_item uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); it public.store_items%rowtype; bal integer;
begin
  if uid is null then raise exception 'not authenticated'; end if;
  if public.is_banned() then raise exception 'banned'; end if;
  select * into it from public.store_items where id = p_item and active;
  if not found then raise exception 'item not available'; end if;
  if exists (select 1 from public.purchases where user_id = uid and item_id = p_item) then
    raise exception 'already owned';
  end if;
  select points into bal from public.profiles where id = uid for update;
  if bal < it.price then raise exception 'insufficient points'; end if;
  update public.profiles set points = points - it.price where id = uid;
  insert into public.purchases (user_id, item_id, price_paid) values (uid, p_item, it.price);
  if it.price > 0 then
    insert into public.points_ledger (user_id, amount, kind, note, ref_id)
      values (uid, -it.price, 'purchase', it.title, it.id);
  end if;
  return jsonb_build_object('balance', bal - it.price);
end $$;

create or replace function public.equip_cosmetic(p_kind text, p_item uuid) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); it public.store_items%rowtype;
begin
  if uid is null then raise exception 'not authenticated'; end if;
  if p_kind not in ('theme','frame') then raise exception 'invalid kind'; end if;
  if p_item is null then
    if p_kind = 'theme' then update public.profiles set theme_item = null where id = uid;
    else update public.profiles set frame_item = null where id = uid; end if;
    return;
  end if;
  select * into it from public.store_items where id = p_item;
  if not found or it.kind <> p_kind then raise exception 'invalid item'; end if;
  if it.price > 0 and not exists (select 1 from public.purchases where user_id = uid and item_id = p_item) then
    raise exception 'not owned';
  end if;
  if p_kind = 'theme' then update public.profiles set theme_item = p_item where id = uid;
  else update public.profiles set frame_item = p_item where id = uid; end if;
end $$;

create or replace function public.admin_stats() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return jsonb_build_object(
    'users', (select count(*) from public.profiles),
    'active_users', (select count(*) from public.profiles where last_seen_at > now() - interval '7 days'),
    'banned_users', (select count(*) from public.profiles where banned),
    'installs', (select count(*) from public.installs),
    'stories', (select count(*) from public.stories where status = 'published'),
    'views', (select coalesce(sum(views), 0) from public.stories),
    'points_given', (select coalesce(sum(amount), 0) from public.points_ledger where amount > 0),
    'ad_impressions', (select coalesce(sum(impressions), 0) from public.ads)
  );
end $$;

create or replace function public.admin_adjust_points(p_user uuid, p_amount integer, p_note text default null)
returns integer language plpgsql security definer set search_path = public as $$
declare cur integer; nb integer; delta integer;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  select points into cur from public.profiles where id = p_user for update;
  if not found then raise exception 'user not found'; end if;
  nb := greatest(cur + p_amount, 0);
  delta := nb - cur;
  update public.profiles set points = nb where id = p_user;
  if delta <> 0 then
    insert into public.points_ledger (user_id, amount, kind, note)
    values (p_user, delta, case when delta >= 0 then 'admin_grant' else 'admin_deduct' end,
            coalesce(nullif(p_note, ''), 'تعديل من الإدارة'));
  end if;
  return nb;
end $$;

create or replace function public.admin_set_ban(p_user uuid, p_banned boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if exists (select 1 from public.profiles where id = p_user and role = 'admin') then
    raise exception 'cannot ban an admin';
  end if;
  update public.profiles set banned = p_banned where id = p_user;
end $$;

-- Public info for the share landing page (works without login, only for normal published stories).
create or replace function public.get_story_public(p_id uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'id', s.id, 'title', s.title, 'narrator', s.narrator, 'description', s.description,
    'cover_url', s.cover_url, 'duration_sec', s.duration_sec)
  from public.stories s
  left join public.categories c on c.id = s.category_id
  where s.id = p_id and s.status = 'published' and (c.id is null or not c.is_exclusive);
$$;

grant execute on function public.register_install(uuid) to anon, authenticated;
grant execute on function public.get_story_public(uuid) to anon, authenticated;

-- ---------- 6. STORAGE (public bucket "hakawi"; only the admin can upload / change / delete) ----------

insert into storage.buckets (id, name, public) values ('hakawi', 'hakawi', true)
on conflict (id) do update set public = true;

drop policy if exists hakawi_public_read on storage.objects;
create policy hakawi_public_read on storage.objects for select using (bucket_id = 'hakawi');
drop policy if exists hakawi_admin_insert on storage.objects;
create policy hakawi_admin_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'hakawi' and public.is_admin());
drop policy if exists hakawi_admin_update on storage.objects;
create policy hakawi_admin_update on storage.objects for update to authenticated
  using (bucket_id = 'hakawi' and public.is_admin());
drop policy if exists hakawi_admin_delete on storage.objects;
create policy hakawi_admin_delete on storage.objects for delete to authenticated
  using (bucket_id = 'hakawi' and public.is_admin());

-- ---------- 7. DEFAULT SETTINGS + STARTER STORE ITEMS (editable by the admin inside the app) ----------

insert into public.app_settings (key, value)
values ('reward', '{"min_duration_sec":600,"points":5,"min_watch_ratio":0.9,"daily_cap":50}'::jsonb)
on conflict (key) do nothing;

insert into public.store_items (id, title, description, kind, price, payload, sort) values
 ('00000000-0000-0000-0000-000000000101', 'ثيم البنفسجي الملكي', 'ألوان بنفسجية ملكية مع لمسات ذهبية', 'theme', 30,
   '{"bg":"#120A2E","surface":"#1F1450","primary":"#A78BFA","secondary":"#F5C451"}', 1),
 ('00000000-0000-0000-0000-000000000102', 'ثيم أزرق المحيط', 'درجات الأزرق الهادئة', 'theme', 40,
   '{"bg":"#06192E","surface":"#0C2B4D","primary":"#38BDF8","secondary":"#FDE68A"}', 2),
 ('00000000-0000-0000-0000-000000000103', 'ثيم الغروب الوردي', 'ألوان دافئة وردية', 'theme', 50,
   '{"bg":"#2A0A1E","surface":"#40142F","primary":"#F472B6","secondary":"#FBBF24"}', 3),
 ('00000000-0000-0000-0000-000000000104', 'إطار الملف الذهبي', 'إطار ذهبي حول صورتك الشخصية', 'frame', 20,
   '{"color":"#F5C451","color2":"#FDE68A"}', 4),
 ('00000000-0000-0000-0000-000000000105', 'إطار النيون', 'إطار نيون متدرج', 'frame', 25,
   '{"color":"#22D3EE","color2":"#A78BFA"}', 5)
on conflict (id) do nothing;
