create extension if not exists "uuid-ossp";

create or replace function trigger_set_updated_at()
    returns trigger as $$ 
    begin
        new.updated_at = current_timestamp;
        return new;
    end;
    $$ language plpgsql;


create schema auth;

create table auth.users (
    id uuid not null primary key default uuid_generate_v4(),
    email varchar unique not null,
    password varchar not null,
    is_admin boolean not null default false,
    created_at timestamp with time zone not null default current_timestamp,
    updated_at timestamp with time zone not null default current_timestamp
);

create trigger set_users_updated_at
    before update on auth.users
    for each row execute procedure trigger_set_updated_at();

create table user_domains (
    id uuid not null primary key default uuid_generate_v4(),
    user_id uuid not null references auth.users (id),
    domain varchar not null,
    created_at timestamp with time zone not null default current_timestamp,
    updated_at timestamp with time zone not null default current_timestamp,

    unique (user_id, domain)
);

create trigger set_user_domains_updated_at
    before update on user_domains
    for each row execute procedure trigger_set_updated_at();

create table user_ports (
    id uuid not null primary key default uuid_generate_v4(),
    user_id uuid not null references auth.users (id),
    ipv4_addrs varchar not null,
    ports varchar not null,
    created_at timestamp with time zone not null default current_timestamp,
    updated_at timestamp with time zone not null default current_timestamp,

    unique (user_id, ipv4_addrs)
);

create trigger set_user_ports_updated_at
    before update on user_ports
    for each row execute procedure trigger_set_updated_at();

create type scan_state as enum ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');
create type scan_type as enum ('DOMAIN', 'SSL', 'HTTP');

create table scans (
    id uuid not null primary key default uuid_generate_v4(),
    user_id uuid references auth.users(id),
    user_domain_id uuid references user_domains (id),
    user_port_id uuid references user_ports (id),
    source_ipv4_addr varchar,
    domain varchar,
    ipv4_addrs varchar,
    ports varchar,
    state scan_state not null default 'PENDING'::scan_state,
    created_at timestamp with time zone not null default current_timestamp,
    updated_at timestamp with time zone not null default current_timestamp

    -- scan should belong to only one of either registered or non registered: user domain or user port
    -- constraint chk_domain_or_port check 
    --     (num_nonnulls(user_domain_id, user_port_id, domain, ipv4_addrs) = 1),

    -- make sure ipv4 addresses always have ports associated with them
    -- constraint chk_ipv4_and_port check ((ipv4_addrs is null and ports is null and user_id is null) or (
    --     ipv4_addrs is not null and ports is not null and user_id is not null
    -- ))

);

create trigger set_scans_updated_at
    before update on scans
    for each row execute procedure trigger_set_updated_at();

create type domain_record as enum 
    ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'DMARC', 'SPF', 'apps');


create table domain_scan_results (
    id uuid not null primary key default uuid_generate_v4(),
    scan_id uuid not null references scans (id),
    record_type domain_record not null,
    record_values varchar not null
);

create type network_protocol as enum ('TCP', 'UDP');

create table port_scan_results (
    id uuid not null primary key default uuid_generate_v4(),
    scan_id uuid not null references scans (id),
    host varchar not null,
    host_state varchar not null,
    port varchar not null,
    port_state varchar not null,
    protocol network_protocol not null
);

create table ssl_cert_results (
    id uuid not null primary key default uuid_generate_v4(),
    scan_result_id uuid not null references port_scan_results (id),
    subject varchar,
    subject_alternative_name varchar not null,
    issuer varchar,
    public_key_type varchar,
    public_key_bits varchar,
    signature_algorithm varchar,
    not_valid_before timestamp with time zone,
    not_valid_after timestamp with time zone,
    md5 varchar,
    sha_1 varchar
);

create table ssl_enum_ciphers_results (
    id uuid not null primary key default uuid_generate_v4(),
    scan_result_id uuid not null references port_scan_results (id),
    cipher_version varchar,
    supported_ciphers varchar,
    compressors varchar,
    cipher_preference varchar,
    warnings varchar
);

create table http_security_headers_results (
    id uuid not null primary key default uuid_generate_v4(),
    scan_result_id uuid not null references port_scan_results (id),
    header varchar not null,
    value varchar not null,
    description varchar
);
