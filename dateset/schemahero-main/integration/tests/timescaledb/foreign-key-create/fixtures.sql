create table users (
  id integer primary key not null,
  email varchar(255) not null
);

create table projects (
  id integer primary key not null,
  name varchar(255) not null
);

create table misc (
  pk varchar(255) primary key not null
);

