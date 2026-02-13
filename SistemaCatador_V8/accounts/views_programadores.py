from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden

from .models import User


# ============================================================
# PERMISSÃO — APENAS PROGRAMADOR
# ============================================================
def apenas_programador(view_func):
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("login_programador")
        if request.user.role != "programador":
            return HttpResponseForbidden("Acesso restrito ao programador.")
        return view_func(request, *args, **kwargs)
    return _wrapped


# ============================================================
# LISTAR PROGRAMADORES
# ============================================================
@login_required(login_url="login_programador")
@apenas_programador
def lista_programadores(request):
    programadores = User.objects.filter(
        role="programador").order_by("username")
    qtd = programadores.count()

    return render(request, "programadores/lista.html", {
        "programadores": programadores,
        "qtd": qtd,
        "maximo": 2,
    })


# ============================================================
# ADICIONAR PROGRAMADOR
#   - Máximo 2 programadores
#   - Senha inicial SEMPRE "0000"
# ============================================================
@login_required(login_url="login_programador")
@apenas_programador
def adicionar_programador(request):

    # Limite de 2 programadores no sistema
    qtd = User.objects.filter(role="programador").count()
    if qtd >= 2:
        messages.error(request, "Limite máximo de 2 programadores atingido.")
        return redirect("lista_programadores")

    if request.method == "POST":
        nome = (request.POST.get("full_name") or "").strip()
        email = (request.POST.get("email") or "").strip().lower()
        username_form = (request.POST.get("username") or "").strip().lower()

        # Validação de nome
        if not nome:
            messages.error(request, "Informe o nome completo.")
            return redirect("adicionar_programador")

        # Validação de e-mail
        if not email:
            messages.error(request, "Informe um e-mail válido.")
            return redirect("adicionar_programador")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Já existe um usuário com esse e-mail.")
            return redirect("adicionar_programador")

        # Username — se veio no formulário, usa; senão, usa parte antes do @
        if username_form:
            username = username_form
        else:
            username = email.split("@")[0]

        # Garante username único
        base_username = username
        contador = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{contador}"
            contador += 1

        # Senha inicial fixa (como você pediu)
        senha_inicial = "0000"

        novo = User.objects.create_user(
            username=username,
            email=email,
            password=senha_inicial,
            full_name=nome,
            role="programador",
        )

        return render(request, "programadores/senha_gerada.html", {
            "username": username,
            "senha": senha_inicial,
            "nome": nome,
        })

    return render(request, "programadores/add.html")


# ============================================================
# EDITAR PROGRAMADOR
#   - Atualiza nome, e-mail
#   - Pode alterar senha (opcional)
# ============================================================
@login_required(login_url="login_programador")
@apenas_programador
def editar_programador(request, pk):
    prog = get_object_or_404(User, pk=pk, role="programador")

    if request.method == "POST":
        nome = (request.POST.get("full_name") or "").strip()
        email = (request.POST.get("email") or "").strip().lower()
        password1 = (request.POST.get("password1") or "").strip()
        password2 = (request.POST.get("password2") or "").strip()

        if not nome:
            messages.error(request, "Informe o nome completo.")
            return redirect("editar_programador", pk=pk)

        if not email:
            messages.error(request, "Informe um e-mail válido.")
            return redirect("editar_programador", pk=pk)

        if User.objects.filter(email=email).exclude(pk=pk).exists():
            messages.error(request, "E-mail já utilizado por outro usuário.")
            return redirect("editar_programador", pk=pk)

        # Atualiza dados básicos
        prog.full_name = nome
        prog.email = email

        # Se quiser trocar senha
        if password1 or password2:
            if password1 != password2:
                messages.error(request, "As senhas não conferem.")
                return redirect("editar_programador", pk=pk)
            prog.set_password(password1)
            messages.success(
                request, "Programador atualizado e senha alterada!")
        else:
            messages.success(request, "Programador atualizado com sucesso!")

        prog.save()

        return redirect("lista_programadores")

    return render(request, "programadores/edit.html", {"prog": prog})


# ============================================================
# EXCLUIR PROGRAMADOR
#   - NÃO permite excluir o último
#   - NÃO permite excluir a si mesmo
# ============================================================
@login_required(login_url="login_programador")
@apenas_programador
def excluir_programador(request, pk):
    prog = get_object_or_404(User, pk=pk, role="programador")
    qtd = User.objects.filter(role="programador").count()

    eh_ultimo = (qtd <= 1)
    eh_proprio = (request.user.pk == prog.pk)

    contexto = {
        "prog": prog,
        "ultimo": eh_ultimo,
        "proprio": eh_proprio,
    }

    # Se for o último programador → mostra mensagem de bloqueio
    if eh_ultimo:
        # Só renderiza a tela explicando, sem apagar
        return render(request, "programadores/delete.html", contexto)

    # Se o usuário estiver tentando excluir a si mesmo
    if eh_proprio:
        # Também não exclui, apenas mostra mensagem
        return render(request, "programadores/delete.html", contexto)

    # Se chegou aqui: não é o último e não é o próprio → pode excluir
    if request.method == "POST":
        prog.delete()
        messages.success(request, "Programador removido com sucesso!")
        return redirect("lista_programadores")

    # Tela normal de confirmação
    return render(request, "programadores/delete.html", contexto)
