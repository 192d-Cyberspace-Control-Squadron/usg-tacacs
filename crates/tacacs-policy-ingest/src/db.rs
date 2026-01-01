// SPDX-License-Identifier: Apache-2.0
use anyhow::Result;
use serde_json::Value;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ingest_runs (
              id UUID PRIMARY KEY,
              repo_id TEXT NOT NULL,
              commit_sha TEXT NOT NULL,
              ref TEXT NOT NULL,
              received_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS policy_versions (
              id UUID PRIMARY KEY,
              repo_id TEXT NOT NULL,
              commit_sha TEXT NOT NULL,
              location_code TEXT NOT NULL,
              policy_json JSONB NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              UNIQUE (repo_id, commit_sha, location_code)
            );

            CREATE TABLE IF NOT EXISTS config_versions (
              id UUID PRIMARY KEY,
              repo_id TEXT NOT NULL,
              commit_sha TEXT NOT NULL,
              location_code TEXT NOT NULL,
              config_json JSONB NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              UNIQUE (repo_id, commit_sha, location_code)
            );

            CREATE TABLE IF NOT EXISTS active_set (
              repo_id TEXT NOT NULL,
              location_code TEXT NOT NULL,
              active_commit_sha TEXT NOT NULL,
              activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              activated_by TEXT NOT NULL,
              PRIMARY KEY (repo_id, location_code)
            );
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_run(&self, repo_id: &str, commit_sha: &str, r#ref: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO ingest_runs (id, repo_id, commit_sha, ref) VALUES ($1,$2,$3,$4)"#,
        )
        .bind(id)
        .bind(repo_id)
        .bind(commit_sha)
        .bind(r#ref)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn upsert_policy(
        &self,
        repo_id: &str,
        commit_sha: &str,
        location_code: &str,
        policy: &Value,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO policy_versions (id, repo_id, commit_sha, location_code, policy_json)
            VALUES ($1,$2,$3,$4,$5)
            ON CONFLICT (repo_id, commit_sha, location_code)
            DO UPDATE SET policy_json = EXCLUDED.policy_json
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo_id)
        .bind(commit_sha)
        .bind(location_code)
        .bind(policy)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_config(
        &self,
        repo_id: &str,
        commit_sha: &str,
        location_code: &str,
        config: &Value,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO config_versions (id, repo_id, commit_sha, location_code, config_json)
            VALUES ($1,$2,$3,$4,$5)
            ON CONFLICT (repo_id, commit_sha, location_code)
            DO UPDATE SET config_json = EXCLUDED.config_json
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo_id)
        .bind(commit_sha)
        .bind(location_code)
        .bind(config)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn promote(
        &self,
        repo_id: &str,
        location_code: &str,
        commit_sha: &str,
        activated_by: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO active_set (repo_id, location_code, active_commit_sha, activated_by)
            VALUES ($1,$2,$3,$4)
            ON CONFLICT (repo_id, location_code)
            DO UPDATE SET active_commit_sha = EXCLUDED.active_commit_sha,
                         activated_at = now(),
                         activated_by = EXCLUDED.activated_by
            "#,
        )
        .bind(repo_id)
        .bind(location_code)
        .bind(commit_sha)
        .bind(activated_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
