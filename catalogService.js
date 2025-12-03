const db = require('../db');
const ServiceError = require('../utils/ServiceError');

const entityQueries = {
	carreras: `
		SELECT id,
		       nombre,
		       totalHoras AS "totalHoras",
		       practicaHoras AS "practicaHoras",
		       teoricaHoras AS "teoricaHoras",
		       colorDiurno AS "colorDiurno",
		       colorVespertino AS "colorVespertino"
		  FROM carreras
		 ORDER BY nombre ASC` ,
	modulos: `
		SELECT id,
		       nombre,
		       carreraId AS "carreraId",
		       COALESCE(totalHoras, 0) AS "totalHoras",
		       COALESCE(horasTeoricas, 0) AS "horasTeoricas",
		       COALESCE(horasPracticas, 0) AS "horasPracticas",
		       COALESCE(horasSemanales, 0) AS "horasSemanales"
		  FROM modulos
		 ORDER BY nombre ASC` ,
	docentes: `
		SELECT d.id,
		       d.rut,
		       d.nombre,
		       d.email,
		       d.carreraId AS "carreraId",
		       d.edad,
		       d.estadoCivil AS "estadoCivil",
		       d.turno,
		       COALESCE(d.activo, TRUE) AS activo,
		       COALESCE(d."contratoHoras", 0) AS "contratoHoras",
		       COALESCE(d."ContratoHoraSemanal", 0) AS "ContratoHoraSemanal",
		       0::NUMERIC AS "horasAsignadas",
		       0::NUMERIC AS "horasTrabajadas",
		       COALESCE(
			       json_agg(
				       json_build_object(
					       'id', dc.carrera_id,
					       'prioridad', COALESCE(dc.prioridad, 1),
					       'activo', COALESCE(dc.activo, TRUE)
				       )
				       ORDER BY COALESCE(dc.prioridad, 1), dc.carrera_id
			       ) FILTER (WHERE dc.carrera_id IS NOT NULL),
			       '[]'::json
		       ) AS "carrerasAsignadas"
		  FROM docentes d
		  LEFT JOIN docente_carrera dc ON dc.docente_id = d.id
		 GROUP BY d.id, d.rut, d.nombre, d.email, d.carreraId, d.edad, d.estadoCivil, d.turno, d.activo, d."contratoHoras", d."ContratoHoraSemanal"
		 ORDER BY d.nombre ASC` ,
	salas: `
		SELECT id,
		       nombre,
		       capacidad
		  FROM salas
		 ORDER BY nombre ASC`
};

async function fetchEntityRows(entity) {
	const query = entityQueries[entity];
	if (!query) {
		throw new ServiceError(`Entidad desconocida: ${entity}`, { statusCode: 400 });
	}
	try {
		const { rows } = await db.query(query);
		return rows;
	} catch (error) {
		throw new ServiceError(`No se pudieron obtener ${entity}`, { cause: error });
	}
}

const getCarreras = () => fetchEntityRows('carreras');
const getModulos = () => fetchEntityRows('modulos');
const getDocentes = () => fetchEntityRows('docentes');
const getSalas = () => fetchEntityRows('salas');

module.exports = {
	getCarreras,
	getModulos,
	getDocentes,
	getSalas
};
