-- DRAFT ONLY: requires security review and isolation tests before use.
-- This file has NOT been executed against the production database.
create schema if not exists staff_private;
revoke all on schema staff_private from public, anon, authenticated;
create table staff_private.invitations (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references auth.users(id),
 employee_id uuid not null,
 department_id uuid not null,
 token_hash bytea not null unique,
 expires_at timestamptz not null,
 used_at timestamptz,
 revoked_at timestamptz,
 foreign key (employee_id, owner_id) references public.employees(id, owner_id) on delete cascade,
 foreign key (department_id, owner_id) references public.departments(id, owner_id) on delete cascade
);
create table staff_private.memberships (
 user_id uuid primary key references auth.users(id) on delete cascade,
 owner_id uuid not null references auth.users(id),
 employee_id uuid not null,
 department_id uuid not null,
 created_at timestamptz not null default now(),
 revoked_at timestamptz,
 foreign key (employee_id, owner_id) references public.employees(id, owner_id) on delete cascade,
 foreign key (department_id, owner_id) references public.departments(id, owner_id) on delete cascade
);
revoke all on all tables in schema staff_private from public, anon, authenticated;
-- Public RPCs are narrowly scoped and explicitly validate the caller.
create function public.draft_create_staff_invite(p_employee uuid)
returns text language plpgsql security definer set search_path = '' as $$
declare v_owner uuid := auth.uid(); v_employee public.employees%rowtype; v_token text;
begin
 if v_owner is null then raise exception 'authentication required'; end if;
 select * into v_employee from public.employees
 where id=p_employee and owner_id=v_owner;
 if not found then raise exception 'employee not found'; end if;
 v_token := encode(extensions.gen_random_bytes(32), 'hex');
 insert into staff_private.invitations(owner_id,employee_id,department_id,token_hash,expires_at)
 values(v_owner,v_employee.id,v_employee.department_id,
 extensions.digest(v_token,'sha256'),now()+interval '48 hours');
 return v_token;
end $$;
revoke all on function public.draft_create_staff_invite(uuid) from public, anon;
grant execute on function public.draft_create_staff_invite(uuid) to authenticated;
create function public.draft_accept_staff_invite(p_token text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_user uuid := auth.uid(); v_inv staff_private.invitations%rowtype;
begin
 if v_user is null then raise exception 'authentication required'; end if;
 if p_token is null or p_token !~ '^[0-9a-f]{64}$' then raise exception 'invalid invitation'; end if;
 update staff_private.invitations
 set used_at=now()
 where token_hash=extensions.digest(p_token,'sha256')
 and used_at is null and revoked_at is null and expires_at>now()
 returning * into v_inv;
 if not found then raise exception 'invalid or expired invitation'; end if;
 if not exists(select 1 from public.employees
   where id=v_inv.employee_id and owner_id=v_inv.owner_id and department_id=v_inv.department_id)
 then raise exception 'employee no longer belongs to department'; end if;
 insert into staff_private.memberships(user_id,owner_id,employee_id,department_id)
 values(v_user,v_inv.owner_id,v_inv.employee_id,v_inv.department_id);
 return true;
end $$;
revoke all on function public.draft_accept_staff_invite(text) from public, anon;
grant execute on function public.draft_accept_staff_invite(text) to authenticated;
-- Not implemented: secure account creation without email, department-scoped read
-- APIs that do not expose colleague phone numbers, revocation, owner UI, QR UI,
-- abuse protection, and automated tests. Do not deploy this draft.
