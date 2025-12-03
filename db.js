const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
	console.warn('DATABASE_URL no está definido. La API responderá 503 hasta configurarlo.');
}

const pool = connectionString
	? new Pool({
			connectionString,
			ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }
		})
	: null;

async function initializeSchema() {
	if (!pool) {
		return;
	}

	const statements = [
		'CREATE EXTENSION IF NOT EXISTS pgcrypto',
		'CREATE EXTENSION IF NOT EXISTS citext',
		`CREATE TABLE IF NOT EXISTS carreras (
			id TEXT PRIMARY KEY,
			nombre TEXT,
			totalHoras INTEGER,
			practicaHoras INTEGER,
			teoricaHoras INTEGER,
			colorDiurno TEXT,
			colorVespertino TEXT,
			"jefeCarrera" TEXT
		)`,
		'ALTER TABLE carreras ADD COLUMN IF NOT EXISTS "jefeCarrera" TEXT',
		`CREATE TABLE IF NOT EXISTS modulos (
			id TEXT PRIMARY KEY,
			nombre TEXT NOT NULL,
			carreraId TEXT REFERENCES carreras(id) ON DELETE SET NULL,
			totalHoras INTEGER DEFAULT 0,
			horasTeoricas NUMERIC(4,1) DEFAULT 0,
			horasPracticas NUMERIC(4,1) DEFAULT 0,
			horasSemanales NUMERIC(4,1) DEFAULT 0,
			"horasSemana" INTEGER DEFAULT 0,
			nivel INTEGER,
			carrera_id TEXT REFERENCES carreras(id) ON DELETE SET NULL,
			codigo_asignatura TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		'ALTER TABLE modulos ADD COLUMN IF NOT EXISTS "horasSemana" INTEGER DEFAULT 0',
		'ALTER TABLE modulos ADD COLUMN IF NOT EXISTS nivel INTEGER',
		'ALTER TABLE modulos ADD COLUMN IF NOT EXISTS carrera_id TEXT',
		'ALTER TABLE modulos ADD COLUMN IF NOT EXISTS codigo_asignatura TEXT',
		`DO $$
DECLARE
	constraint_exists BOOLEAN;
BEGIN
	SELECT EXISTS (
		SELECT 1
		FROM information_schema.constraint_column_usage
		WHERE table_name = 'modulos'
		  AND constraint_name = 'modulos_carrera_id_fkey'
	) INTO constraint_exists;
	IF NOT constraint_exists THEN
		BEGIN
			ALTER TABLE modulos
				ADD CONSTRAINT modulos_carrera_id_fkey
				FOREIGN KEY (carrera_id) REFERENCES carreras(id) ON DELETE SET NULL;
		EXCEPTION WHEN duplicate_object THEN
			-- constraint already exists under another name
			NULL;
		END;
	END IF;
END $$`,
		'UPDATE modulos SET carrera_id = "carreraId" WHERE "carreraId" IS NOT NULL AND (carrera_id IS NULL OR carrera_id <> "carreraId")',
		'UPDATE modulos SET "carreraId" = carrera_id WHERE carrera_id IS NOT NULL AND ("carreraId" IS NULL OR "carreraId" <> carrera_id)',
		'CREATE INDEX IF NOT EXISTS idx_modulos_carrera_id ON modulos(carrera_id)',
		'CREATE INDEX IF NOT EXISTS idx_modulos_codigo_asignatura ON modulos(codigo_asignatura)',
		`CREATE OR REPLACE FUNCTION sync_modulos_carrera_columns()
RETURNS TRIGGER AS $$
BEGIN
	IF NEW."carreraId" IS NOT NULL AND (NEW.carrera_id IS NULL OR NEW.carrera_id <> NEW."carreraId") THEN
		NEW.carrera_id := NEW."carreraId";
	ELSIF NEW.carrera_id IS NOT NULL AND (NEW."carreraId" IS NULL OR NEW."carreraId" <> NEW.carrera_id) THEN
		NEW."carreraId" := NEW.carrera_id;
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql`,
		'DROP TRIGGER IF EXISTS trg_sync_modulos_carrera ON modulos',
		`CREATE TRIGGER trg_sync_modulos_carrera
	BEFORE INSERT OR UPDATE ON modulos
	FOR EACH ROW
	EXECUTE FUNCTION sync_modulos_carrera_columns()`,
		`CREATE TABLE IF NOT EXISTS docentes (
			id VARCHAR(20) PRIMARY KEY,
			rut VARCHAR(20) UNIQUE NOT NULL,
			nombre VARCHAR(255) NOT NULL,
			email VARCHAR(255),
			titulo TEXT,
			"contratoHoras" NUMERIC(5,2) DEFAULT 0,
			"ContratoHoraSemanal" NUMERIC(4,1) DEFAULT 0 CHECK ("ContratoHoraSemanal" <= 40),
			carreraId TEXT REFERENCES carreras(id) ON DELETE SET NULL,
			edad INTEGER,
			estadoCivil TEXT,
			turno TEXT,
			activo BOOLEAN DEFAULT TRUE,
			"TotalHrsModulos" NUMERIC(6,1) DEFAULT 0,
			"Hrs Teóricas" NUMERIC(4,1) DEFAULT 0,
			"Hrs Prácticas" NUMERIC(4,1) DEFAULT 0,
			"Total hrs Semana" NUMERIC(4,1) DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS carreraId TEXT REFERENCES carreras(id) ON DELETE SET NULL`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS carrera_id TEXT`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS edad INTEGER`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS estadoCivil TEXT`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS turno TEXT`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT TRUE`,
		`ALTER TABLE docentes ADD COLUMN IF NOT EXISTS "ContratoHoraSemanal" NUMERIC(4,1) DEFAULT 0 CHECK ("ContratoHoraSemanal" <= 40)`,
		`DO $$
DECLARE
	constraint_exists BOOLEAN;
BEGIN
	SELECT EXISTS (
		SELECT 1
		FROM information_schema.constraint_column_usage
		WHERE table_name = 'docentes'
		  AND constraint_name = 'docentes_carrera_id_fkey'
	) INTO constraint_exists;
	IF NOT constraint_exists THEN
		BEGIN
			ALTER TABLE docentes
				ADD CONSTRAINT docentes_carrera_id_fkey
				FOREIGN KEY (carrera_id) REFERENCES carreras(id) ON DELETE SET NULL;
		EXCEPTION WHEN duplicate_object THEN
			NULL;
		END;
	END IF;
END $$`,
		'UPDATE docentes SET carrera_id = "carreraId" WHERE "carreraId" IS NOT NULL AND (carrera_id IS NULL OR carrera_id <> "carreraId")',
		'UPDATE docentes SET "carreraId" = carrera_id WHERE carrera_id IS NOT NULL AND ("carreraId" IS NULL OR "carreraId" <> carrera_id)',
		`CREATE OR REPLACE FUNCTION sync_docentes_carrera_columns()
RETURNS TRIGGER AS $$
BEGIN
	IF NEW."carreraId" IS NOT NULL AND (NEW.carrera_id IS NULL OR NEW.carrera_id <> NEW."carreraId") THEN
		NEW.carrera_id := NEW."carreraId";
	ELSIF NEW.carrera_id IS NOT NULL AND (NEW."carreraId" IS NULL OR NEW."carreraId" <> NEW.carrera_id) THEN
		NEW."carreraId" := NEW.carrera_id;
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql`,
		'DROP TRIGGER IF EXISTS trg_sync_docentes_carrera ON docentes',
		`CREATE TRIGGER trg_sync_docentes_carrera
	BEFORE INSERT OR UPDATE ON docentes
	FOR EACH ROW
	EXECUTE FUNCTION sync_docentes_carrera_columns()`,
		`CREATE TABLE IF NOT EXISTS docente_carrera (
			docente_id VARCHAR(20) NOT NULL REFERENCES docentes(id) ON DELETE CASCADE,
			carrera_id TEXT NOT NULL REFERENCES carreras(id) ON DELETE CASCADE,
			prioridad INTEGER DEFAULT 1,
			activo BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (docente_id, carrera_id)
		)`,
		'CREATE INDEX IF NOT EXISTS idx_docente_carrera_docente ON docente_carrera (docente_id)',
		'CREATE INDEX IF NOT EXISTS idx_docente_carrera_carrera ON docente_carrera (carrera_id)',
		`INSERT INTO docente_carrera (docente_id, carrera_id, prioridad, activo)
		 SELECT d.id,
		        COALESCE(d.carrera_id, d."carreraId"),
		        1,
		        COALESCE(d.activo, TRUE)
		   FROM docentes d
		  WHERE COALESCE(d.carrera_id, d."carreraId") IS NOT NULL
		ON CONFLICT (docente_id, carrera_id) DO NOTHING`,
		`CREATE OR REPLACE FUNCTION update_modified_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = NOW();
			RETURN NEW;
		END;
		$$ language 'plpgsql'`,
		`DROP TRIGGER IF EXISTS update_docentes_modtime ON docentes`,
		`CREATE TRIGGER update_docentes_modtime
		    BEFORE UPDATE ON docentes
		    FOR EACH ROW
		    EXECUTE FUNCTION update_modified_column()`,
		`CREATE TABLE IF NOT EXISTS salas (
			id TEXT PRIMARY KEY,
			nombre TEXT,
			capacidad INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS templates (
			id TEXT PRIMARY KEY,
			moduloId TEXT,
			docenteId TEXT,
			salaId TEXT,
			startDate TEXT,
			time TEXT,
			duration REAL,
			until TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			title TEXT,
			start TEXT,
			"end" TEXT,
			extendedProps JSONB
		)`,
		`CREATE TABLE IF NOT EXISTS sala_restriccion (
			id SERIAL PRIMARY KEY,
			sala_id TEXT NOT NULL REFERENCES salas(id) ON DELETE CASCADE,
			carrera_id TEXT NOT NULL REFERENCES carreras(id) ON DELETE CASCADE,
			UNIQUE (sala_id, carrera_id)
		)`,
		'CREATE INDEX IF NOT EXISTS idx_sala_restriccion_sala ON sala_restriccion(sala_id)',
		'CREATE INDEX IF NOT EXISTS idx_sala_restriccion_carrera ON sala_restriccion(carrera_id)',
		`CREATE TABLE IF NOT EXISTS docente_semana_horas (
			docente_id VARCHAR(20) REFERENCES docentes(id) ON DELETE CASCADE,
			semana INTEGER NOT NULL,
			"anio" INTEGER NOT NULL,
			bloques_usados INTEGER DEFAULT 0,
			horas_usadas NUMERIC(5,2) GENERATED ALWAYS AS (bloques_usados * 35.0 / 60.0) STORED,
			PRIMARY KEY (docente_id, semana, "anio")
		)`,
		`CREATE TABLE IF NOT EXISTS auth_role (
			id SERIAL PRIMARY KEY,
			code TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT
		)`,
		`INSERT INTO auth_role (code, name, description) VALUES
			('admin', 'Administrador', 'Acceso completo al panel'),
			('docente', 'Docente', 'Puede consultar/modificar su horario'),
			('viewer', 'Lector', 'Solo lectura de reportes')
		ON CONFLICT (code) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS auth_user (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			full_name TEXT NOT NULL,
			email CITEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			must_reset_pwd BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_user_email ON auth_user (email)`,
		`CREATE TABLE IF NOT EXISTS auth_user_role (
			user_id UUID REFERENCES auth_user(id) ON DELETE CASCADE,
			role_id INTEGER REFERENCES auth_role(id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, role_id)
		)`,
		`CREATE TABLE IF NOT EXISTS auth_session_token (
			token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
			issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			metadata JSONB DEFAULT '{}'::jsonb
		)`,
		`CREATE INDEX IF NOT EXISTS idx_session_user ON auth_session_token (user_id)`,
		`CREATE TABLE IF NOT EXISTS auth_login_audit (
			id BIGSERIAL PRIMARY KEY,
			user_id UUID REFERENCES auth_user(id) ON DELETE SET NULL,
			email_input CITEXT NOT NULL,
			ip_address INET,
			user_agent TEXT,
			was_success BOOLEAN NOT NULL,
			reason TEXT,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`
	];

	for (const statement of statements) {
		await pool.query(statement);
	}

	await ensureSeedAdmin();
}

async function ensureSeedAdmin() {
	if (!pool) return;
	const seedEmail = process.env.DEFAULT_ADMIN_EMAIL;
	const seedPassword = process.env.DEFAULT_ADMIN_PASSWORD;
	const seedName = process.env.DEFAULT_ADMIN_NAME || process.env.DEFAULT_ADMIN_USERNAME || 'Administrador Conexia';

	if (!seedEmail || !seedPassword) {
		console.warn('DEFAULT_ADMIN_EMAIL o DEFAULT_ADMIN_PASSWORD no están definidos. No se creará un administrador por defecto.');
		return;
	}

	const existing = await pool.query('SELECT id FROM auth_user WHERE LOWER(email) = LOWER($1) LIMIT 1', [seedEmail]);
	let userId = existing.rows[0]?.id;
	if (!userId) {
		const passwordHash = await bcrypt.hash(seedPassword, 10);
		const inserted = await pool.query(
			'INSERT INTO auth_user (full_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
			[seedName, seedEmail, passwordHash]
		);
		userId = inserted.rows[0]?.id;
	}
	if (userId) {
		await pool.query(
			`INSERT INTO auth_user_role (user_id, role_id)
			 SELECT $1, r.id FROM auth_role r WHERE r.code = 'admin'
			 ON CONFLICT DO NOTHING`,
			[userId]
		);
	}
}

initializeSchema().catch((err) => {
	console.error('Error creando las tablas base en PostgreSQL', err);
});

module.exports = {
	pool,
	ready: Boolean(pool),
	query: async (text, params = []) => {
		if (!pool) {
			throw new Error('Pool de PostgreSQL no inicializado.');
		}
		return pool.query(text, params);
	}
};