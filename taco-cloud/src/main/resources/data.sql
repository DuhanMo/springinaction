insert into users (username, password) values ('user1', '123123');
insert into users (username, password) values ('user2', '123123');

insert into authorities (username, authority)
values ('user1', 'ROLE_USER');
insert into authorities (username, authority)
values ('user2', 'ROLE_USER');

commit;