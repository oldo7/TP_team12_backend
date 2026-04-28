from django.db import migrations

CONTROL_CLASSES = [
    {
        "name": "Symmetric Encryption",
        "description": "Encrypts data using a shared secret key (e.g. AES-128/256). Provides confidentiality. Bypassing requires breaking the cipher or obtaining the key.",
        "fr_et": 19,   # >6 months
        "fr_se": 8,    # Multiple experts
        "fr_koC": 11,  # Critical
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 9,    # Multiple bespoke
    },
    {
        "name": "Asymmetric Encryption",
        "description": "Encrypts data using a public/private key pair (e.g. RSA, ECC). Breaking the cipher is computationally infeasible with current technology.",
        "fr_et": 99,   # Not practical
        "fr_se": 8,    # Multiple experts
        "fr_koC": 11,  # Critical
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 9,    # Multiple bespoke
    },
    {
        "name": "Message Authentication Code (MAC)",
        "description": "Ensures message integrity and authenticity using a shared secret (e.g. HMAC-SHA256). Forging a valid MAC without the key is computationally infeasible.",
        "fr_et": 19,   # >6 months
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Digital Signature",
        "description": "Cryptographic proof of message origin and integrity using a private key (e.g. ECDSA). Forging a signature requires access to the private key.",
        "fr_et": 99,   # Not practical
        "fr_se": 8,    # Multiple experts
        "fr_koC": 11,  # Critical
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 7,    # Bespoke
    },
    {
        "name": "TLS / DTLS",
        "description": "Secures communication channels using certificate-based mutual authentication and symmetric session encryption. Breaks require defeating PKI or the session cipher.",
        "fr_et": 99,   # Not practical
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Secure Boot",
        "description": "Verifies the integrity and authenticity of firmware/software at startup using a hardware root of trust. Bypassing requires physical access and specialized hardware.",
        "fr_et": 19,   # >6 months
        "fr_se": 8,    # Multiple experts
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 10,  # Difficult
        "fr_eq": 7,    # Bespoke
    },
    {
        "name": "Code Signing",
        "description": "Software updates and binaries are signed with a private key. The device only executes code with a valid signature from a trusted authority.",
        "fr_et": 19,   # >6 months
        "fr_se": 8,    # Multiple experts
        "fr_koC": 11,  # Critical
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 7,    # Bespoke
    },
    {
        "name": "Secure Key Storage (HSM / TPM)",
        "description": "Cryptographic keys are stored and used inside tamper-resistant hardware (HSM, TPM, SE). Extraction requires defeating hardware protections.",
        "fr_et": 99,   # Not practical
        "fr_se": 8,    # Multiple experts
        "fr_koC": 11,  # Critical
        "fr_WoO": 10,  # Difficult
        "fr_eq": 9,    # Multiple bespoke
    },
    {
        "name": "Firewall / Packet Filtering",
        "description": "Network-level filtering of traffic by source, destination, protocol, and port. Bypassing requires evading filter rules or exploiting allowed traffic.",
        "fr_et": 10,   # <=3 months
        "fr_se": 3,    # Proficient
        "fr_koC": 3,   # Restricted
        "fr_WoO": 4,   # Moderate
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Intrusion Detection System (IDS)",
        "description": "Monitors traffic or system behaviour for anomalies and raises alerts. Bypassing requires crafting attacks that evade detection signatures or baselines.",
        "fr_et": 4,    # <=1 month
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 10,  # Difficult
        "fr_eq": 0,    # Standard
    },
    {
        "name": "Access Control / Authentication",
        "description": "Restricts access to resources via credentials, tokens, or certificates. Bypassing requires credential theft, brute force, or session hijacking.",
        "fr_et": 10,   # <=3 months
        "fr_se": 3,    # Proficient
        "fr_koC": 3,   # Restricted
        "fr_WoO": 1,   # Easy
        "fr_eq": 0,    # Standard
    },
    {
        "name": "Role-Based Access Control (RBAC)",
        "description": "Limits operations to principals with the required role. Bypassing requires privilege escalation or compromising a privileged account.",
        "fr_et": 10,   # <=3 months
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 4,   # Moderate
        "fr_eq": 0,    # Standard
    },
    {
        "name": "Anti-Replay Protection",
        "description": "Uses sequence numbers, timestamps, or nonces to reject replayed messages. Bypassing requires real-time man-in-the-middle capability.",
        "fr_et": 4,    # <=1 month
        "fr_se": 3,    # Proficient
        "fr_koC": 3,   # Restricted
        "fr_WoO": 4,   # Moderate
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Rate Limiting",
        "description": "Throttles the number of requests or messages from a source in a time window. Bypassing requires distributing the attack across many sources.",
        "fr_et": 1,    # <=1 week
        "fr_se": 0,    # Layman
        "fr_koC": 0,   # Public
        "fr_WoO": 4,   # Moderate
        "fr_eq": 0,    # Standard
    },
    {
        "name": "Input Validation / Sanitization",
        "description": "Validates and sanitizes all external input before processing. Bypassing requires finding unvalidated inputs or edge cases in the validation logic.",
        "fr_et": 4,    # <=1 month
        "fr_se": 3,    # Proficient
        "fr_koC": 3,   # Restricted
        "fr_WoO": 1,   # Easy
        "fr_eq": 0,    # Standard
    },
    {
        "name": "Secure OTA Update",
        "description": "Over-the-air software updates are authenticated and integrity-checked before installation. Bypassing requires a valid signed update or breaking the update channel.",
        "fr_et": 19,   # >6 months
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 10,  # Difficult
        "fr_eq": 7,    # Bespoke
    },
    {
        "name": "CAN Bus Message Authentication (SecOC)",
        "description": "Authenticates CAN/CAN-FD frames using a MAC per AUTOSAR SecOC. Forging authenticated frames requires the session key.",
        "fr_et": 19,   # >6 months
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 0,   # Unnecessary/unlimited
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Physical Access Protection",
        "description": "Physical barriers, tamper seals, or enclosures that prevent or detect unauthorized physical access to hardware.",
        "fr_et": 4,    # <=1 month
        "fr_se": 3,    # Proficient
        "fr_koC": 0,   # Public
        "fr_WoO": 10,  # Difficult
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Debug Interface Disable",
        "description": "JTAG, UART, and other debug interfaces are permanently disabled or locked via fuse bits in production firmware. Bypassing requires decapping or fault injection.",
        "fr_et": 17,   # <=6 months
        "fr_se": 8,    # Multiple experts
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 10,  # Difficult
        "fr_eq": 7,    # Bespoke
    },
    {
        "name": "Secure Logging / Audit Trail",
        "description": "Events are logged in a tamper-evident, append-only store. Covering tracks requires defeating log integrity protections.",
        "fr_et": 10,   # <=3 months
        "fr_se": 6,    # Expert
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 10,  # Difficult
        "fr_eq": 0,    # Standard
    },
    {
        "name": "Memory Protection (ASLR / DEP / MPU)",
        "description": "OS or hardware memory protections prevent code injection and execution in non-executable regions. Bypassing requires an information leak plus a ROP chain.",
        "fr_et": 10,   # <=3 months
        "fr_se": 8,    # Multiple experts
        "fr_koC": 7,   # Sensitive
        "fr_WoO": 4,   # Moderate
        "fr_eq": 4,    # Specialized
    },
    {
        "name": "Secure Session Management",
        "description": "Short-lived session tokens with proper expiry, rotation, and revocation. Bypassing requires token theft or session fixation within the validity window.",
        "fr_et": 4,    # <=1 month
        "fr_se": 3,    # Proficient
        "fr_koC": 3,   # Restricted
        "fr_WoO": 4,   # Moderate
        "fr_eq": 0,    # Standard
    },
]


def seed_control_classes(apps, schema_editor):
    ControlClass = apps.get_model('api', 'ControlClass')
    for entry in CONTROL_CLASSES:
        ControlClass.objects.create(**entry)


def remove_control_classes(apps, schema_editor):
    ControlClass = apps.get_model('api', 'ControlClass')
    ControlClass.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_control_class'),
    ]

    operations = [
        migrations.RunPython(seed_control_classes, remove_control_classes),
    ]
