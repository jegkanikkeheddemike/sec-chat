create database sec_chat;
use sec_chat;

create or replace table users(
    user_id uuid primary key default uuid(),
    public_key Text not null
);