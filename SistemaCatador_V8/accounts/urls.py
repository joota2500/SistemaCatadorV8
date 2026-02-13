from django.urls import path
from . import views
from . import views_programadores   # módulo de rotas dos programadores

urlpatterns = [

    # ===============================
    # LOGIN / SENHAS / INÍCIO
    # ===============================
    path("", views.index, name="index"),

    path("esqueci-senha/", views.esqueci_senha, name="esqueci_senha"),
    path("redefinir-senha/", views.redefinir_senha, name="redefinir_senha"),

    path("login-programador/", views.login_programador, name="login_programador"),
    path("logout/", views.logout_view, name="logout"),

    # ===============================
    # PAINÉIS
    # ===============================
    path("painel-municipio/", views.painel_municipio, name="painel_municipio"),
    path("painel-programador/", views.painel_programador,
         name="painel_programador"),

    # ===============================
    # RELATÓRIOS / SEGURANÇA
    # ===============================
    path("relatorios/logins/", views.relatorio_logins, name="relatorio_logins"),

    # ===============================
    # CRUD MUNICÍPIOS
    # ===============================
    path("municipios/novo/", views.add_municipio, name="add_municipio"),
    path("municipios/<int:pk>/editar/",
         views.edit_municipio, name="edit_municipio"),
    path("municipios/<int:pk>/excluir/",
         views.delete_municipio, name="delete_municipio"),

    # ===============================
    # CRUD ENCARREGADOS
    # ===============================
    path("encarregados/novo/", views.add_encarregado, name="add_encarregado"),
    path("encarregados/<int:pk>/editar/",
         views.edit_encarregado, name="edit_encarregado"),
    path("encarregados/<int:pk>/excluir/",
         views.delete_encarregado, name="delete_encarregado"),

    # ===============================
    # 🔥 CRUD PROGRAMADORES (NOVO)
    # ===============================
    path("programadores/", views_programadores.lista_programadores,
         name="lista_programadores"),
    path("programadores/novo/", views_programadores.adicionar_programador,
         name="adicionar_programador"),
    path("programadores/<int:pk>/editar/",
         views_programadores.editar_programador, name="editar_programador"),
    path("programadores/<int:pk>/excluir/",
         views_programadores.excluir_programador, name="excluir_programador"),
]
