const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const fsPromises = require('fs').promises;
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const app = express();
require('dotenv').config();

// Configuración de Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());



// Configuración de la base de datos
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Conectar a la base de datos
db.connect(err => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a la base de datos');
});

// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

// Middlewares de autenticación
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session.userId && (role.includes(req.session.tipo_usuario) || req.session.tipo_usuario === role)) {
      next();
    } else {
      res.send('Acceso denegado');
    }
  };
}

// ==============================================
// RUTAS ORIGINALES
// ==============================================

// Registro de usuario
app.post('/registrar', async (req, res) => {
  const { nombre_usuario, password, codigo_acceso } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);

  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  db.query(query, [codigo_acceso], (err, results) => {
    if (err || results.length === 0) {
      return res.send('Código de acceso inválido');
    }
    const tipo_usuario = results[0].tipo_usuario;
    db.query('INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)', 
      [nombre_usuario, passwordHash, tipo_usuario], (err) => {
        if (err) {
          return res.send('Error al registrar el usuario.');
        }
        res.redirect('/login.html');
      });
  });
});

// Iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;

  db.query('SELECT * FROM usuarios WHERE nombre_usuario = ?', 
    [nombre_usuario], async (err, results) => {
      if (err || results.length === 0) {
        return res.send('Usuario no encontrado.');
      }

      const user = results[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (match) {
        req.session.userId = user.id;
        req.session.nombre_usuario = user.nombre_usuario;
        req.session.tipo_usuario = user.tipo_usuario;
        
        res.redirect('/');
      } else {
        res.send('Contraseña incorrecta.');
      }
    });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});




// Ruta para obtener categorías con tipo (actualizada)
app.get('/api/categorias', (req, res) => {
  db.query('SELECT id, nombre FROM categorias_equipos', (err, results) => {
    if (err) {
      console.error('Error al obtener categorías:', err);
      return res.status(500).json({ error: 'Error al obtener categorías' });
    }
    res.json(results);
  });
});
// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ 
    tipo_usuario: req.session.tipo_usuario,
    userId: req.session.userId 
  });
});
// Ruta para eliminar usuario solo administrador 
app.post('/eliminar_usuario', requireLogin, requireRole('admin'), (req, res) => {
  const {id} = req.body;

  const query = 'DELETE FROM usuarios WHERE id=(?)';
  db.query(query, [id], (err, result) => {
    if (err) {
      return res.send('Error al eliminar al usuario.');
    }
    res.send(`Usuario eliminado de la base de datos.`);
  });
});


// Configuración de Multer para carga de archivos
const upload = multer({ 
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype.includes('excel') || file.mimetype.includes('spreadsheet')) {
      cb(null, true);
    } else {
      cb(new Error('Solo se permiten archivos Excel'), false);
    }
  }
});

// Ruta para manejar la carga de archivos Excel
// Ruta para carga de categorías desde Excel (solo admin)


// ==============================================
// NUEVAS RUTAS PARA EQUIPOS
// ==============================================

// 1. Obtener equipos según rol
// Ruta corregida para obtener equipos
app.get('/api/equipos', requireLogin, (req, res) => {
  const query = `
    SELECT 
      e.id, 
      e.nombre, 
      e.descripcion,
      e.es_aprobado,
      c.nombre AS categoria_nombre,
      c.tipo AS categoria_tipo
    FROM equipos e
    LEFT JOIN categorias_equipos c ON e.categoria_id = c.id
    WHERE e.estado = 'activo'
    ${req.session.tipo_usuario !== 'admin' ? 'AND e.es_aprobado = 1' : ''}
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error en consulta de equipos:', err);
      return res.status(500).json({ error: 'Error al obtener equipos' });
    }
    
    // Asegúrate de devolver un array incluso si está vacío
    res.json(Array.isArray(results) ? results : []);
  });
});
// 2. Búsqueda de equipos
// Ruta corregida para búsqueda de equipos
app.get('/api/equipos/buscar', requireLogin, (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Término de búsqueda requerido' });

  const query = `
    SELECT 
      e.id, 
      e.nombre, 
      e.descripcion,
      e.es_aprobado,
      c.nombre AS categoria_nombre,
      c.tipo AS categoria_tipo
    FROM equipos e
    LEFT JOIN categorias_equipos c ON e.categoria_id = c.id
    WHERE (e.nombre LIKE ? OR e.descripcion LIKE ?)
    AND e.estado = 'activo'
    ${req.session.tipo_usuario !== 'admin' ? 'AND e.es_aprobado = 1' : ''}
  `;
  
  const searchTerm = `%${q}%`;
  
  db.query(query, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error('Error en búsqueda de equipos:', err);
      return res.status(500).json({ error: 'Error al buscar equipos' });
    }
    res.json(results);
  });
});

// 3. Crear equipo (Admin)
app.post('/api/admin/equipos', requireLogin, requireRole('admin'), (req, res) => {
  const { nombre, descripcion, categoria_id } = req.body;
  
  if (!nombre || !categoria_id) {
    return res.status(400).json({ error: 'Nombre y categoría son requeridos' });
  }

  db.query(
    `INSERT INTO equipos 
    (nombre, descripcion, categoria_id, usuario_id, es_aprobado)
    VALUES (?, ?, ?, ?, TRUE)`,
    [nombre, descripcion || null, categoria_id, req.session.userId],
    (err, result) => {
      if (err) {
        console.error('Error al crear equipo:', err);
        return res.status(500).json({ error: 'Error al crear equipo' });
      }
      res.json({ id: result.insertId });
    }
  );
});
// 4. Eliminar equipo (Admin)
app.delete('/api/admin/equipos/:id', requireLogin, requireRole('admin'), (req, res) => {
  db.query(
    'UPDATE equipos SET estado = "inactivo" WHERE id = ?',
    [req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Error al eliminar equipo' });
      res.json({ message: 'Equipo eliminado' });
    }
  );
});

// 5. Crear equipo (Vendedor)
app.post('/api/vendedor/equipos', requireLogin, requireRole('vendedor'), (req, res) => {
  const { nombre, descripcion, categoria_id } = req.body;
  
  if (!nombre || !categoria_id) {
    return res.status(400).json({ error: 'Nombre y categoría son requeridos' });
  }

  db.query(
    `INSERT INTO equipos 
    (nombre, descripcion, categoria_id, usuario_id, es_aprobado)
    VALUES (?, ?, ?, ?, FALSE)`,
    [nombre, descripcion || null, categoria_id, req.session.userId],
    (err, result) => {
      if (err) {
        console.error('Error al crear equipo:', err);
        return res.status(500).json({ error: 'Error al crear equipo' });
      }
      res.json({ 
        id: result.insertId,
        message: 'Equipo enviado para aprobación' 
      });
    }
  );
});

// 6. Eliminar equipo (Vendedor)
app.delete('/api/vendedor/equipos/:id', requireLogin, requireRole('vendedor'), (req, res) => {
  db.query(
    'SELECT usuario_id FROM equipos WHERE id = ?',
    [req.params.id],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ error: 'Equipo no encontrado' });
      }
      
      if (results[0].usuario_id !== req.session.userId) {
        return res.status(403).json({ error: 'No tienes permiso para eliminar este equipo' });
      }

      db.query(
        'UPDATE equipos SET estado = "inactivo" WHERE id = ?',
        [req.params.id],
        (err) => {
          if (err) return res.status(500).json({ error: 'Error al eliminar equipo' });
          res.json({ message: 'Equipo eliminado' });
        }
      );
    }
  );
});

// 7. Aprobar equipo (Admin)
app.post('/api/admin/equipos/:id/aprobar', requireLogin, requireRole('admin'), (req, res) => {
  db.query(
    'UPDATE equipos SET es_aprobado = TRUE WHERE id = ?',
    [req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Error al aprobar equipo' });
      res.json({ message: 'Equipo aprobado' });
    }
  );
});

// 8. Editar equipo (Admin)
app.put('/api/admin/equipos/:id', requireLogin, requireRole('admin'), (req, res) => {
  const { nombre, descripcion, categoria_id } = req.body;
  
  if (!nombre || !categoria_id) {
    return res.status(400).json({ error: 'Nombre y categoría son requeridos' });
  }

  db.query(
    `UPDATE equipos 
     SET nombre = ?, descripcion = ?, categoria_id = ?
     WHERE id = ?`,
    [nombre, descripcion || null, categoria_id, req.params.id],
    (err) => {
      if (err) {
        console.error('Error al actualizar equipo:', err);
        return res.status(500).json({ error: 'Error al actualizar equipo' });
      }
      res.json({ message: 'Equipo actualizado correctamente' });
    }
  );
});

// 9. Obtener un equipo específico
app.get('/api/equipos/:id', requireLogin, (req, res) => {
  db.query(
    `SELECT e.*, c.nombre as categoria_nombre, c.tipo as categoria_tipo
     FROM equipos e
     LEFT JOIN categorias_equipos c ON e.categoria_id = c.id
     WHERE e.id = ?`,
    [req.params.id],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Error al obtener equipo' });
      if (results.length === 0) return res.status(404).json({ error: 'Equipo no encontrado' });
      
      res.json(results[0]);
    }
  );
});


// Ruta para enviar consultas (deberás adaptarlo a tu backend)
app.post('/api/consultas', upload.single('adjunto'), (req, res) => {
  const { equipo_id, pregunta } = req.body;
  const adjunto = req.file ? req.file.path : null;
  
  // Guardar la consulta en la base de datos
  // Notificar al vendedor correspondiente
  
  res.json({ success: true, message: 'Consulta recibida' });
});


// Obtener consultas para el vendedor
app.get('/api/consultas', (req, res) => {
  // Verificar que el usuario es vendedor
  if (req.user.tipo !== 'vendedor') {
    return res.status(403).json({ error: 'No autorizado' });
  }
  
  // Obtener consultas asignadas a este vendedor o sin asignar
  db.query(`
    SELECT c.*, e.nombre as equipo_nombre, u.nombre as cliente_nombre
    FROM consultas c
    JOIN equipos e ON c.equipo_id = e.id
    LEFT JOIN usuarios u ON c.cliente_id = u.id
    WHERE c.vendedor_id IS NULL OR c.vendedor_id = ?
    ORDER BY c.fecha DESC
  `, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Responder a una consulta
app.post('/api/consultas/:id/responder', (req, res) => {
  const { respuesta } = req.body;
  
  db.query(`
    UPDATE consultas 
    SET respuesta = ?, fecha_respuesta = NOW(), vendedor_id = ?
    WHERE id = ?
  `, [respuesta, req.user.id, req.params.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Opcional: Notificar al cliente por email
    // ...
    
    res.json({ success: true });
  });
});


// Obtener respuestas pendientes para el cliente
app.get('/api/consultas/respuestas-pendientes', (req, res) => {
  if (req.user.tipo !== 'cliente') {
    return res.status(403).json({ error: 'No autorizado' });
  }
  
  db.query(`
    SELECT COUNT(*) as count 
    FROM consultas 
    WHERE cliente_id = ? AND respuesta IS NOT NULL AND leida = false
  `, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ count: results[0].count });
  });
});

// Obtener todas las consultas del cliente
app.get('/api/consultas/mis-consultas', (req, res) => {
  if (req.user.tipo !== 'cliente') {
    return res.status(403).json({ error: 'No autorizado' });
  }
  
  db.query(`
    SELECT c.*, e.nombre as equipo_nombre, u.nombre as vendedor_nombre
    FROM consultas c
    JOIN equipos e ON c.equipo_id = e.id
    LEFT JOIN usuarios u ON c.vendedor_id = u.id
    WHERE c.cliente_id = ?
    ORDER BY c.fecha DESC
  `, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Marcar notificaciones como leídas
app.post('/api/consultas/marcar-leidas', (req, res) => {
  if (req.user.tipo !== 'cliente') {
    return res.status(403).json({ error: 'No autorizado' });
  }
  
  db.query(`
    UPDATE consultas 
    SET leida = true 
    WHERE cliente_id = ? AND respuesta IS NOT NULL
  `, [req.user.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});






// Obtener todos los usuarios (solo admin)
app.get('/api/usuarios', requireLogin, requireRole('admin'), (req, res) => {
  db.query('SELECT id, nombre_usuario, tipo_usuario FROM usuarios', (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al obtener usuarios' });
    res.json(results);
  });
});

// Eliminar usuario (solo admin)
app.delete('/api/usuarios/:id', requireLogin, requireRole('admin'), (req, res) => {
  // No permitir auto-eliminación
  if (parseInt(req.params.id) === req.session.userId) {
    return res.status(403).json({ error: 'No puedes eliminarte a ti mismo' });
  }

  db.query('DELETE FROM usuarios WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Error al eliminar usuario' });
    res.json({ message: 'Usuario eliminado' });
  });
});




// Ruta para servir equipos.html
app.get('/equipos.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/equipos.html'));
});

// Ruta para gestión de equipos (admin)
app.get('/admin/equipos/gestion', requireLogin, requireRole('admin'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin-equipos.html'));
});


// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000/login.html');
});