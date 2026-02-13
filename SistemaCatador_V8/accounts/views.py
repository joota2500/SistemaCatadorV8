import unicodedata
import re
from datetime import timedelta
import random
import string

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

from .models import Municipality, User, PasswordResetCode, LoginAttempt


# ============================================================
# CONFIGS DE SEGURANÇA PARA LOGIN
# ============================================================
LOCK_MAX_ATTEMPTS = 5          # número de tentativas
LOCK_TIME_MINUTES = 2          # janela de tempo (minutos)

# Regex simples e profissional para validar e-mail
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ============================================================
# FUNÇÕES AUXILIARES GERAIS
# ============================================================
def email_valido(email: str) -> bool:
    """
    Valida formato básico de e-mail.
    Ex: nome@dominio.com
    """
    if not email:
        return False
    return EMAIL_REGEX.match(email) is not None


def senha_ja_usada(senha_clara: str, excluir_user_id=None) -> bool:
    """
    Verifica se a senha em texto claro já é usada por outro usuário no sistema.
    Usa check_password para comparar com os hashes existentes.
    """
    if not senha_clara:
        return False

    qs = User.objects.all()
    if excluir_user_id is not None:
        qs = qs.exclude(pk=excluir_user_id)

    for u in qs:
        if u.check_password(senha_clara):
            return True
    return False


def normalizar_credencial(texto: str) -> str:
    """Remove acentos, espaços e deixa tudo minúsculo."""
    if not texto:
        return ""
    texto = texto.strip().lower()
    texto_sem_acentos = ''.join(
        c for c in unicodedata.normalize('NFD', texto)
        if unicodedata.category(c) != 'Mn'
    )
    return texto_sem_acentos.replace(" ", "")


# ============================================================
# FUNÇÕES AUXILIARES DE LOGIN (TENTATIVAS / BLOQUEIO)
# ============================================================
def _contar_falhas_recentes(username, municipality, is_programador):
    """
    Conta quantas falhas ocorreram nos últimos LOCK_TIME_MINUTES
    para o mesmo usuário (e município, se não for programador).
    """
    agora = timezone.now()
    qs = LoginAttempt.objects.filter(
        username_typed=username or "",
        is_programador=is_programador,
        success=False,
        created_at__gte=agora - timedelta(minutes=LOCK_TIME_MINUTES),
    )
    if not is_programador and municipality is not None:
        qs = qs.filter(municipality=municipality)
    return qs.count()


def _esta_bloqueado(username, municipality, is_programador):
    """
    Verifica se já atingiu o limite de falhas na janela de tempo configurada.
    """
    falhas = _contar_falhas_recentes(username, municipality, is_programador)
    return falhas >= LOCK_MAX_ATTEMPTS


def _enviar_alerta_bloqueio(username, municipality, is_programador):
    """
    Envia e-mail para todos os programadores ativos avisando
    que houve muitas tentativas de login para um usuário.
    """
    programadores = User.objects.filter(
        role="programador",
        is_active=True
    ).exclude(email__isnull=True).exclude(email="")

    if not programadores:
        return

    if is_programador:
        alvo = f"PROGRAMADOR: {username}"
        muni = "—"
    else:
        alvo = f"ENCARREGADO: {username}"
        muni = municipality.name if municipality else "Não informado"

    assunto = "Alerta de segurança — muitas tentativas de login"
    mensagem = (
        "Atenção,\n\n"
        "Foi detectado um possível ataque de força bruta ao Sistema Catador V8.\n\n"
        f"Usuário alvo: {alvo}\n"
        f"Município: {muni}\n"
        f"Tentativas falhas em sequência: {LOCK_MAX_ATTEMPTS} ou mais em "
        f"{LOCK_TIME_MINUTES} minutos.\n\n"
        "Recomenda-se verificar com o responsável e, se necessário, "
        "alterar a senha deste usuário.\n\n"
        "Mensagem automática do Sistema Catador V8."
    )

    emails = [p.email for p in programadores]
    send_mail(
        subject=assunto,
        message=mensagem,
        from_email=getattr(
            settings,
            "DEFAULT_FROM_EMAIL",
            "naoresponda@sistemacatadorv8.com"
        ),
        recipient_list=emails,
        fail_silently=True,
    )


def _registrar_tentativa(request, username, municipality, success, is_programador):
    """
    Registra a tentativa de login e dispara alerta quando atingir o limite.
    """
    ip = request.META.get("REMOTE_ADDR", None)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]

    tentativa = LoginAttempt.objects.create(
        username_typed=username or "",
        municipality=municipality,
        ip_address=ip,
        user_agent=user_agent,
        success=success,
        is_programador=is_programador,
        locked=False,
    )

    # Se foi falha, verificar se atingiu o limite
    if not success:
        falhas = _contar_falhas_recentes(
            username, municipality, is_programador
        )
        if falhas >= LOCK_MAX_ATTEMPTS:
            tentativa.locked = True
            tentativa.save(update_fields=["locked"])
            _enviar_alerta_bloqueio(username, municipality, is_programador)


# ============================================================
# GUARDIÃO — SOMENTE PROGRAMADOR
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
# TELA INICIAL — LOGIN DO ENCARREGADO
# ============================================================
def index(request):

    municipios = Municipality.objects.filter(is_active=True)
    encarregados = User.objects.filter(role="municipal", is_active=True)

    error = None

    if request.method == "POST":
        municipality_id = request.POST.get("municipality")
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Buscar município (se existir)
        try:
            municipio = Municipality.objects.get(
                id=municipality_id, is_active=True
            )
        except Municipality.DoesNotExist:
            municipio = None

        # Verificar bloqueio antes de autenticar
        if _esta_bloqueado(username, municipio, is_programador=False):
            error = (
                f"Muitas tentativas falhas. "
                f"Aguarde {LOCK_TIME_MINUTES} minutos e tente novamente."
            )
            _registrar_tentativa(
                request,
                username,
                municipio,
                success=False,
                is_programador=False
            )
        else:
            user = authenticate(request, username=username, password=password)

            # Segurança: usuário municipal, município correto e vínculo correto
            if (
                not user
                or user.role != "municipal"
                or not municipio
                or user.municipality_id != municipio.id
            ):
                error = "Encarregado ou município incorreto."
                _registrar_tentativa(
                    request,
                    username,
                    municipio,
                    success=False,
                    is_programador=False
                )
            else:
                _registrar_tentativa(
                    request,
                    username,
                    municipio,
                    success=True,
                    is_programador=False
                )
                login(request, user)
                return redirect("painel_municipio")

    return render(request, "index.html", {
        "municipalities": municipios,
        "encarregados": encarregados,
        "error": error,
    })


# ============================================================
# ESQUECI MINHA SENHA — ENVIA CÓDIGO POR E-MAIL
# ============================================================
def esqueci_senha(request):
    municipios = Municipality.objects.filter(is_active=True)
    error = None
    success = None

    if request.method == "POST":
        municipality_id = request.POST.get("municipality")
        username = request.POST.get("username")

        try:
            municipio = Municipality.objects.get(id=municipality_id)
        except Municipality.DoesNotExist:
            municipio = None

        try:
            user = User.objects.get(username=username, role="municipal")
        except User.DoesNotExist:
            user = None

        # Segurança: não revelar quem é válido
        if not municipio or not user or user.municipality_id != municipio.id:
            error = "Município ou usuário incorreto."
            return render(request, "esqueci_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        if not user.email:
            error = "Este usuário não possui e-mail cadastrado. Solicite ao programador."
            return render(request, "esqueci_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        # Gerar código de 6 dígitos
        codigo = "".join(random.choices(string.digits, k=6))

        # Invalidar códigos antigos
        PasswordResetCode.objects.filter(
            user=user, is_used=False
        ).update(is_used=True)

        # Criar novo código
        PasswordResetCode.objects.create(
            user=user,
            code=codigo
        )

        mensagem = (
            f"Olá {user.full_name or user.username},\n\n"
            "Seu código de redefinição de senha é:\n\n"
            f"{codigo}\n\n"
            "Ele vale por 30 minutos.\n"
        )

        send_mail(
            subject="Recuperação de Senha - Sistema Catador V8",
            message=mensagem,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        success = "Código enviado para o e-mail cadastrado!"
        return render(request, "esqueci_senha.html", {
            "municipalities": municipios,
            "success": success
        })

    return render(request, "esqueci_senha.html", {
        "municipalities": municipios
    })


# ============================================================
# REDEFINIR SENHA — USANDO CÓDIGO
# ============================================================
def redefinir_senha(request):
    municipios = Municipality.objects.filter(is_active=True)
    error = None
    success = None

    if request.method == "POST":
        municipality_id = request.POST.get("municipality")
        username = request.POST.get("username")
        codigo = request.POST.get("code")
        nova_senha = request.POST.get("password1")
        confirma_senha = request.POST.get("password2")

        if nova_senha != confirma_senha:
            error = "As senhas não coincidem."
            return render(request, "redefinir_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        try:
            municipio = Municipality.objects.get(id=municipality_id)
        except Municipality.DoesNotExist:
            municipio = None

        try:
            user = User.objects.get(username=username, role="municipal")
        except User.DoesNotExist:
            user = None

        if not municipio or not user or user.municipality_id != municipio.id:
            error = "Município ou usuário incorreto."
            return render(request, "redefinir_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        # Buscar código válido
        codigo_obj = PasswordResetCode.objects.filter(
            user=user,
            code=codigo,
            is_used=False
        ).order_by("-created_at").first()

        if not codigo_obj:
            error = "Código inválido ou já utilizado."
            return render(request, "redefinir_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        # Verificar validade (30 min)
        limite = codigo_obj.created_at + timedelta(minutes=30)
        if timezone.now() > limite:
            codigo_obj.is_used = True
            codigo_obj.save()
            error = "Código expirado. Solicite outro."
            return render(request, "redefinir_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        # Regra: login != senha
        if user.username and nova_senha and user.username == nova_senha:
            error = "Login e senha não podem ser iguais."
            return render(request, "redefinir_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        # Regra: senha não pode estar sendo usada por outro usuário
        if senha_ja_usada(nova_senha, excluir_user_id=user.pk):
            error = "Esta senha já está sendo utilizada por outro usuário. Por segurança, escolha outra."
            return render(request, "redefinir_senha.html", {
                "municipalities": municipios,
                "error": error
            })

        # Redefinir senha
        user.set_password(nova_senha)
        user.save()

        codigo_obj.is_used = True
        codigo_obj.save()

        success = "Senha redefinida com sucesso!"
        return render(request, "redefinir_senha.html", {
            "municipalities": municipios,
            "success": success
        })

    return render(request, "redefinir_senha.html", {
        "municipalities": municipios
    })


# ============================================================
# LOGIN DO PROGRAMADOR
# ============================================================
def login_programador(request):
    error = None

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Bloqueio para programador
        if _esta_bloqueado(username, None, is_programador=True):
            error = (
                f"Muitas tentativas falhas. "
                f"Aguarde {LOCK_TIME_MINUTES} minutos e tente novamente."
            )
            _registrar_tentativa(
                request,
                username,
                None,
                success=False,
                is_programador=True
            )
        else:
            user = authenticate(request, username=username, password=password)

            if user and user.role == "programador":
                _registrar_tentativa(
                    request,
                    username,
                    None,
                    success=True,
                    is_programador=True
                )
                login(request, user)
                return redirect("painel_programador")

            error = "Usuário ou senha incorretos."
            _registrar_tentativa(
                request,
                username,
                None,
                success=False,
                is_programador=True
            )

    return render(request, "admin_login.html", {"error": error})


# ============================================================
# LOGOUT
# ============================================================
def logout_view(request):
    logout(request)
    return redirect("index")


# ============================================================
# PAINEL DO PROGRAMADOR
# ============================================================
@login_required
@apenas_programador
def painel_programador(request):
    municipios = Municipality.objects.all().order_by("name")
    encarregados = User.objects.filter(role="municipal").order_by("username")

    programadores = User.objects.filter(role="programador")
    prog_count = programadores.count()

    return render(request, "painel_admin.html", {
        "municipios": municipios,
        "encarregados": encarregados,
        "programadores": programadores,
        "prog_count": prog_count,
    })


# ============================================================
# RELATÓRIO DE TENTATIVAS DE LOGIN
# ============================================================
@login_required
@apenas_programador
def relatorio_logins(request):
    tentativas = LoginAttempt.objects.select_related(
        "municipality"
    ).order_by("-created_at")[:500]

    return render(request, "relatorios/logins.html", {
        "tentativas": tentativas,
        "max_tentativas": LOCK_MAX_ATTEMPTS,
        "janela_minutos": LOCK_TIME_MINUTES,
    })


# ============================================================
# PAINEL DO MUNICÍPIO
# ============================================================
@login_required
def painel_municipio(request):
    if request.user.role != "municipal":
        return HttpResponseForbidden(
            "Acesso permitido apenas para encarregados municipais."
        )
    return render(request, "painel_municipio.html")


# ============================================================
# CRUD MUNICÍPIOS
# ============================================================
@login_required
@apenas_programador
def add_municipio(request):

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        slug = (request.POST.get("slug") or "").strip()
        is_active = request.POST.get("is_active") == "True"
        logo = request.FILES.get("logo")

        # Validação básica
        if not name or not slug:
            messages.error(request, "Informe nome e slug do município.")
            return redirect("add_municipio")

        if Municipality.objects.filter(slug=slug).exists():
            messages.error(request, "Já existe um município com esse slug.")
            return redirect("add_municipio")

        if Municipality.objects.filter(name__iexact=name).exists():
            messages.error(request, "Já existe um município com esse nome.")
            return redirect("add_municipio")

        Municipality.objects.create(
            name=name,
            slug=slug,
            is_active=is_active,
            logo=logo
        )

        messages.success(request, f"Município {name} criado com sucesso!")
        return redirect("painel_programador")

    return render(request, "forms/add_municipio.html")


@login_required
@apenas_programador
def edit_municipio(request, pk):
    municipio = Municipality.objects.get(pk=pk)

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        slug = (request.POST.get("slug") or "").strip()
        is_active = request.POST.get("is_active") == "True"

        if not name or not slug:
            messages.error(request, "Informe nome e slug do município.")
            return redirect("edit_municipio", pk=pk)

        # Verificar duplicidade (excluindo o próprio)
        if Municipality.objects.filter(slug=slug).exclude(pk=pk).exists():
            messages.error(request, "Já existe outro município com esse slug.")
            return redirect("edit_municipio", pk=pk)

        if Municipality.objects.filter(name__iexact=name).exclude(pk=pk).exists():
            messages.error(request, "Já existe outro município com esse nome.")
            return redirect("edit_municipio", pk=pk)

        municipio.name = name
        municipio.slug = slug
        municipio.is_active = is_active

        if "logo" in request.FILES:
            municipio.logo = request.FILES["logo"]

        municipio.save()
        messages.success(request, "Município atualizado!")
        return redirect("painel_programador")

    return render(request, "forms/edit_municipio.html", {"municipio": municipio})


@login_required
@apenas_programador
def delete_municipio(request, pk):
    municipio = Municipality.objects.get(pk=pk)

    if request.method == "POST":
        municipio.delete()
        messages.success(request, "Município removido com sucesso!")
        return redirect("painel_programador")

    return render(request, "forms/delete_municipio.html", {"municipio": municipio})


# ============================================================
# CRUD ENCARREGADOS (1 MUNICÍPIO = 1 ENCARREGADO)
# ============================================================
@login_required
@apenas_programador
def add_encarregado(request):

    municipios = Municipality.objects.filter(is_active=True)

    if request.method == "POST":
        name = (request.POST.get("full_name") or "").strip()
        nickname = request.POST.get("nickname")
        cpf = request.POST.get("cpf")
        birth_date = request.POST.get("birth_date") or None
        phone = request.POST.get("phone")
        address = request.POST.get("address")

        email = (request.POST.get("email") or "").strip().lower()
        municipality_id = request.POST.get("municipality")

        # Novos campos (login/senha manual)
        username_manual = (request.POST.get("username") or "").strip().lower()
        password_manual = (request.POST.get("password") or "").strip()

        confirm_username = (request.POST.get("confirm_username") or "").strip()
        confirm_password = (request.POST.get("confirm_password") or "").strip()

        # ================================
        # VALIDAÇÕES BÁSICAS
        # ================================
        if not name:
            messages.error(request, "Informe o nome completo do encarregado.")
            return redirect("add_encarregado")

        if not municipality_id:
            messages.error(request, "Selecione um município.")
            return redirect("add_encarregado")

        try:
            municipio = Municipality.objects.get(pk=municipality_id)
        except Municipality.DoesNotExist:
            messages.error(request, "Município inválido.")
            return redirect("add_encarregado")

        # Regra de ouro: 1 município = 1 encarregado
        if User.objects.filter(
            role="municipal",
            municipality=municipio
        ).exists():
            messages.error(
                request,
                "Já existe um encarregado vinculado a este município. "
                "Edite o encarregado atual ou remova-o antes de cadastrar outro."
            )
            return redirect("add_encarregado")

        # E-mail é obrigatório, formato válido e único
        if not email:
            messages.error(request, "Informe um e-mail válido.")
            return redirect("add_encarregado")

        if not email_valido(email):
            messages.error(
                request,
                "Informe um e-mail em formato válido (ex: nome@dominio.com)."
            )
            return redirect("add_encarregado")

        if User.objects.filter(email=email).exists():
            messages.error(
                request,
                "Já existe um usuário cadastrado com este e-mail."
            )
            return redirect("add_encarregado")

        # ================================
        # FUNÇÃO AUXILIAR LOCAL (sem acentos)
        # ================================
        def _sem_acentos(txt: str) -> str:
            return "".join(
                c for c in unicodedata.normalize("NFD", txt)
                if unicodedata.category(c) != "Mn"
            )

        # ================================
        # LOGIN (USERNAME)
        # ================================
        if username_manual and confirm_username == "usar_manual":
            # Sem espaços
            if " " in username_manual:
                messages.error(
                    request,
                    "O login (usuário) não pode conter espaços."
                )
                return redirect("add_encarregado")

            # Sem acentos
            if username_manual != _sem_acentos(username_manual):
                messages.error(
                    request,
                    "O login (usuário) não pode conter acentos."
                )
                return redirect("add_encarregado")

            # Único no sistema inteiro
            if User.objects.filter(username=username_manual).exists():
                messages.error(
                    request,
                    "Este login já está sendo utilizado por outro usuário."
                )
                return redirect("add_encarregado")

            username = username_manual
        else:
            # Gera login automático a partir do nome (sem acento e sem espaço)
            base_username = normalizar_credencial(name)
            if not base_username:
                base_username = "encarregado"

            username = base_username
            contador = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{contador}"
                contador += 1

        # ================================
        # SENHA
        # ================================
        def gerar_senha_automatica(municipio_obj):
            while True:
                prefix = (municipio_obj.name[:3].lower()
                          if municipio_obj and municipio_obj.name else "enc")
                prefix = _sem_acentos(prefix) or "enc"
                aleatorio = "".join(random.choices(string.digits, k=3))
                candidata = f"enc_{prefix}{aleatorio}"

                # Regra: login ≠ senha
                if username and candidata == username:
                    continue

                # Regra: senha não pode existir em outro usuário
                if senha_ja_usada(candidata):
                    continue

                return candidata

        if password_manual and confirm_password == "usar_manual":
            # Sem espaço
            if " " in password_manual:
                messages.error(request, "A senha não pode conter espaços.")
                return redirect("add_encarregado")

            # Sem acento
            if password_manual != _sem_acentos(password_manual):
                messages.error(request, "A senha não pode conter acentos.")
                return redirect("add_encarregado")

            if len(password_manual) < 4:
                messages.error(
                    request,
                    "A senha deve ter no mínimo 4 caracteres."
                )
                return redirect("add_encarregado")

            # Regra: login ≠ senha
            if username and password_manual == username:
                messages.error(
                    request,
                    "Login e senha não podem ser iguais. "
                    "Escolha outro login ou outra senha."
                )
                return redirect("add_encarregado")

            # Regra: senha única no sistema
            if senha_ja_usada(password_manual):
                messages.error(
                    request,
                    "Esta senha já está sendo utilizada por outro usuário. "
                    "Por segurança, escolha outra senha."
                )
                return redirect("add_encarregado")

            senha_final = password_manual
        else:
            # Gera senha automática (já garantindo não repetir e não ser igual ao login)
            senha_final = gerar_senha_automatica(municipio)

        # ================================
        # CRIAÇÃO DO USUÁRIO
        # ================================
        user = User.objects.create_user(
            username=username,
            password=senha_final,
            full_name=name,
            nickname=nickname,
            cpf=cpf,
            birth_date=birth_date,
            phone=phone,
            address=address,
            municipality=municipio,
            role="municipal",
            email=email,
        )

        if "photo" in request.FILES:
            user.photo = request.FILES["photo"]
            user.save()

        # Mostra tela com a senha (seja manual ou automática)
        return render(request, "forms/senha_encarregado.html", {
            "senha": senha_final,
            "nome": name,
            "username": username,
            "municipio": municipio.name,
        })

    # GET
    return render(request, "forms/add_encarregado.html", {
        "municipios": municipios
    })


@login_required
@apenas_programador
def edit_encarregado(request, pk):

    user = User.objects.get(pk=pk)
    municipios = Municipality.objects.filter(is_active=True)

    if request.method == "POST":
        # ================================
        # CAMPOS BÁSICOS
        # ================================
        full_name = (request.POST.get("full_name") or "").strip()
        username = (request.POST.get("username") or "").strip().lower()
        password_manual = (request.POST.get("password_manual") or "").strip()
        gerar_senha = request.POST.get("gerar_senha") == "1"

        user.nickname = request.POST.get("nickname")
        user.cpf = request.POST.get("cpf")
        user.birth_date = request.POST.get("birth_date") or None
        user.phone = request.POST.get("phone")
        user.address = request.POST.get("address")
        user.permission_level = request.POST.get("permission_level")
        new_municipio_id = request.POST.get("municipality")
        user.is_active = request.POST.get("is_active") == "True"
        email = (request.POST.get("email") or "").strip().lower()

        # ================================
        # VALIDAÇÕES
        # ================================
        if not full_name:
            messages.error(request, "Informe o nome completo do encarregado.")
            return redirect("edit_encarregado", pk=pk)

        if not email:
            messages.error(
                request, "E-mail obrigatório para recuperação de senha."
            )
            return redirect("edit_encarregado", pk=pk)

        if not email_valido(email):
            messages.error(
                request,
                "Informe um e-mail em formato válido (ex: nome@dominio.com)."
            )
            return redirect("edit_encarregado", pk=pk)

        # Checar se outro usuário já usa este e-mail
        if User.objects.filter(email=email).exclude(pk=user.pk).exists():
            messages.error(
                request,
                "Já existe outro usuário utilizando este e-mail."
            )
            return redirect("edit_encarregado", pk=pk)

        if " " in username:
            messages.error(
                request, "O login (username) não pode conter espaços."
            )
            return redirect("edit_encarregado", pk=pk)

        username_sem_acentos = ''.join(
            c for c in unicodedata.normalize('NFD', username)
            if unicodedata.category(c) != 'Mn'
        )

        if username != username_sem_acentos:
            messages.error(request, "O login não pode conter acentos.")
            return redirect("edit_encarregado", pk=pk)

        if User.objects.filter(username=username).exclude(pk=user.pk).exists():
            messages.error(
                request, "Este login já está sendo usado por outro usuário."
            )
            return redirect("edit_encarregado", pk=pk)

        user.username = username
        user.full_name = full_name
        user.email = email

        # ================================
        # LÓGICA DE SENHA
        # ================================
        # Função auxiliar local para não repetir senha nem igualar login
        def gerar_senha_auto_para_user(u: User):
            while True:
                prefix = u.municipality.name[:3].lower(
                ) if u.municipality else "enc"
                prefix = ''.join(
                    c for c in unicodedata.normalize('NFD', prefix)
                    if unicodedata.category(c) != 'Mn'
                ) or "enc"
                aleatorio = "".join(random.choices(string.digits, k=3))
                candidata = f"enc_{prefix}{aleatorio}"

                # login ≠ senha
                if username and candidata == username:
                    continue

                # senha não pode já existir em outro usuário
                if senha_ja_usada(candidata, excluir_user_id=u.pk):
                    continue

                return candidata

        if gerar_senha:
            nova_senha = gerar_senha_auto_para_user(user)
            user.set_password(nova_senha)
            messages.success(
                request, f"Senha gerada automaticamente: {nova_senha}"
            )

        elif password_manual:
            if " " in password_manual:
                messages.error(request, "A senha não pode conter espaços.")
                return redirect("edit_encarregado", pk=pk)

            senha_sem_acentos = ''.join(
                c for c in unicodedata.normalize('NFD', password_manual)
                if unicodedata.category(c) != 'Mn'
            )

            if password_manual != senha_sem_acentos:
                messages.error(request, "A senha não pode conter acentos.")
                return redirect("edit_encarregado", pk=pk)

            if len(password_manual) < 4:
                messages.error(
                    request, "A senha deve ter no mínimo 4 caracteres."
                )
                return redirect("edit_encarregado", pk=pk)

            # Regra: login ≠ senha
            if username and password_manual == username:
                messages.error(
                    request,
                    "Login e senha não podem ser iguais. "
                    "Escolha outra senha."
                )
                return redirect("edit_encarregado", pk=pk)

            # Regra: senha não pode estar em outro usuário
            if senha_ja_usada(password_manual, excluir_user_id=user.pk):
                messages.error(
                    request,
                    "Esta senha já está sendo utilizada por outro usuário. "
                    "Por segurança, escolha outra."
                )
                return redirect("edit_encarregado", pk=pk)

            user.set_password(password_manual)
            messages.success(request, "Senha alterada manualmente.")

        # ================================
        # MUNICÍPIO
        # ================================
        if new_municipio_id:
            try:
                novo_municipio = Municipality.objects.get(pk=new_municipio_id)
            except Municipality.DoesNotExist:
                messages.error(request, "Município inválido.")
                return redirect("edit_encarregado", pk=pk)

            if User.objects.filter(
                role="municipal",
                municipality=novo_municipio
            ).exclude(pk=user.pk).exists():
                messages.error(
                    request,
                    "Este município já possui um encarregado. "
                    "Remova ou edite o encarregado existente."
                )
                return redirect("edit_encarregado", pk=pk)

            user.municipality = novo_municipio

        # ================================
        # FOTO
        # ================================
        if "photo" in request.FILES:
            user.photo = request.FILES["photo"]

        user.save()
        messages.success(request, "Encarregado atualizado com sucesso!")
        return redirect("painel_programador")

    return render(request, "forms/edit_encarregado.html", {
        "user": user,
        "municipios": municipios
    })


@login_required
@apenas_programador
def delete_encarregado(request, pk):
    user = User.objects.get(pk=pk)

    if request.method == "POST":
        user.delete()
        messages.success(request, "Encarregado removido!")
        return redirect("painel_programador")

    return render(request, "forms/delete_encarregado.html", {"user": user})
