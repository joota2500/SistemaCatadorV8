from django.db import models
from django.db.models import Q
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.conf import settings
from django.utils import timezone


# ============================================================
# MUNICÍPIOS
# ============================================================
class Municipality(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=60, unique=True)
    is_active = models.BooleanField(default=True)

    # Logomarca opcional
    logo = models.ImageField(
        upload_to="municipios/logos/",
        blank=True,
        null=True
    )

    class Meta:
        verbose_name = "Município"
        verbose_name_plural = "Municípios"
        ordering = ['name']

    def _str_(self):
        return self.name


# ============================================================
# USUÁRIO PERSONALIZADO
# ============================================================
class User(AbstractUser):
    ROLE_CHOICES = [
        ("programador", "Programador (Acesso Total)"),
        ("municipal", "Usuário Municipal"),
    ]

    PERMISSION_CHOICES = [
        ("full", "Acesso Completo"),
        ("view", "Somente Visualização"),
        ("download", "Visualizar e Baixar"),
    ]

    # ------------------------------------------------------------
    # PERMISSÕES E VÍNCULO
    # ------------------------------------------------------------
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default="municipal"
    )

    municipality = models.ForeignKey(
        "Municipality",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="users"
    )

    permission_level = models.CharField(
        max_length=20,
        choices=PERMISSION_CHOICES,
        default="full"
    )

    # ------------------------------------------------------------
    # CAMPOS PESSOAIS
    # ------------------------------------------------------------
    full_name = models.CharField(
        "Nome Completo", max_length=150, blank=True, null=True
    )
    nickname = models.CharField(
        "Apelido", max_length=50, blank=True, null=True
    )

    cpf = models.CharField(
        "CPF",
        max_length=14,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^\d{3}\.\d{3}\.\d{3}\-\d{2}$',
                message="CPF deve estar no formato XXX.XXX.XXX-XX",
            )
        ],
    )

    birth_date = models.DateField("Data de Nascimento", blank=True, null=True)
    phone = models.CharField("Telefone", max_length=20, blank=True, null=True)
    address = models.CharField(
        "Endereço", max_length=255, blank=True, null=True)

    # Foto do encarregado
    photo = models.ImageField(
        upload_to="encarregados/fotos/",
        blank=True,
        null=True
    )

    # ------------------------------------------------------------
    # EMAIL — OBRIGATÓRIO E ÚNICO
    # ------------------------------------------------------------
    email = models.EmailField(
        unique=True,
        blank=False,
        null=False,
        verbose_name="E-mail",
        help_text="E-mail obrigatório para acesso ao sistema."
    )

    class Meta:
        verbose_name = "Usuário"
        verbose_name_plural = "Usuários"

        # 🔒 Regra: um município só pode ter 1 usuário municipal vinculado
        constraints = [
            models.UniqueConstraint(
                fields=["municipality"],
                condition=Q(role="municipal"),
                name="unique_municipality_for_municipal_user",
            ),
        ]

    # ------------------------------------------------------------
    # Métodos úteis
    # ------------------------------------------------------------
    def is_programador(self):
        return self.role == "programador"

    def is_municipal_user(self):
        return self.role == "municipal"

    def _str_(self):
        if self.full_name:
            return f"{self.username} ({self.full_name})"
        return self.username


# ============================================================
# MODELO — CÓDIGO DE RECUPERAÇÃO DE SENHA
# ============================================================
class PasswordResetCode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reset_codes"
    )
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Código de recuperação"
        verbose_name_plural = "Códigos de recuperação"

    def _str_(self):
        return f"ResetCode({self.user.username} - {self.code})"


# ============================================================
# MODELO — LOG DE TENTATIVAS DE LOGIN
# ============================================================
class LoginAttempt(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)

    username_typed = models.CharField("Usuário digitado", max_length=150)

    municipality = models.ForeignKey(
        Municipality,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="login_attempts",
        verbose_name="Município"
    )

    ip_address = models.GenericIPAddressField("IP", null=True, blank=True)

    user_agent = models.CharField(
        "Navegador", max_length=255, blank=True)

    success = models.BooleanField("Sucesso", default=False)

    is_programador = models.BooleanField(
        "Tentativa do programador?",
        default=False
    )

    locked = models.BooleanField(
        "Bloqueio por excesso?",
        default=False
    )

    class Meta:
        verbose_name = "Tentativa de Login"
        verbose_name_plural = "Tentativas de Login"
        ordering = ["-created_at"]

    def _str_(self):
        tipo = "Programador" if self.is_programador else "Encarregado"
        status = "OK" if self.success else "ERRO"
        return f"[{self.created_at}] {tipo} - {self.username_typed} ({status})"
