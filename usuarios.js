document.addEventListener('DOMContentLoaded', function() {
  cargarUsuarios();
  
  // Configurar búsqueda
  document.getElementById('busqueda-usuarios').addEventListener('input', function() {
    buscarUsuarios(this.value);
  });
});

function cargarUsuarios() {
  fetch('/api/usuarios')
    .then(response => response.json())
    .then(usuarios => mostrarUsuarios(usuarios))
    .catch(error => console.error('Error:', error));
}

function mostrarUsuarios(usuarios) {
  const container = document.getElementById('lista-usuarios');
  container.innerHTML = '';
  
  usuarios.forEach(usuario => {
    const card = document.createElement('div');
    card.className = 'usuario-card';
    card.innerHTML = `
      <h3>${usuario.nombre_usuario}</h3>
      <p>Tipo: ${usuario.tipo_usuario}</p>
      <button class="btn-eliminar" data-id="${usuario.id}">Eliminar</button>
    `;
    container.appendChild(card);
  });
  
  // Agregar eventos a los botones
  document.querySelectorAll('.btn-eliminar').forEach(btn => {
    btn.addEventListener('click', eliminarUsuario);
  });
}

function eliminarUsuario(event) {
  const idUsuario = event.target.dataset.id;
  if (confirm('¿Está seguro de eliminar este usuario?')) {
    fetch(`/api/usuarios/${idUsuario}`, {
      method: 'DELETE'
    })
    .then(response => {
      if (!response.ok) throw new Error('Error al eliminar');
      return response.json();
    })
    .then(() => cargarUsuarios())
    .catch(error => console.error('Error:', error));
  }
}