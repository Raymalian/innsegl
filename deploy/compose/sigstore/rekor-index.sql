-- SPDX-License-Identifier: Apache-2.0
-- Rekor's search index database and the one user that may touch it (#451, ADR-0010 amendment 2026-10-05).
-- trillian-db runs this with --init-file at EVERY start, so a database volume created before the index moved here gets the user too.
-- MySQL 5.7 reads an init file one statement per line, without comments inside a statement.
-- DROP then CREATE, not CREATE IF NOT EXISTS: measured, the image's first-boot entrypoint deletes the user's mysql.user row but not its mysql.db grant, after which IF NOT EXISTS skips the create and the GRANT fails.
-- Rekor creates its own table (EntryIndex) on first connect.
CREATE DATABASE IF NOT EXISTS rekor_index;
DROP USER IF EXISTS 'rekor'@'%';
CREATE USER 'rekor'@'%' IDENTIFIED BY 'rekor-index';
GRANT ALL PRIVILEGES ON rekor_index.* TO 'rekor'@'%';
