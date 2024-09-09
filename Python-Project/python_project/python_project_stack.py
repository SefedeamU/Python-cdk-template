from aws_cdk import (
    Stack,
    CfnParameter,
    CfnOutput,
    Fn
)
import aws_cdk.aws_iam as iam
import aws_cdk.aws_ec2 as ec2
from constructs import Construct

class PythonProjectStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        instance_name = CfnParameter(self, "InstanceName",
            type="String",
            default="MV Reemplazar",
            description="Nombre de la instancia a crear"
        )

        ami = CfnParameter(self, "AMI",
            type="String",
            default="ami-0aa28dab1f2852040",
            description="ID de AMI"
        )

        vpc = ec2.Vpc(self, "VPC")

        security_group = ec2.SecurityGroup(self, "InstanceSecurityGroup",
            vpc=vpc,
            description="Permitir tráfico SSH y HTTP desde cualquier lugar",
            allow_all_outbound=True
        )

        security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Permitir tráfico SSH")
        security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80), "Permitir tráfico HTTP")

        key_pair = ec2.KeyPair.from_key_pair_name(self, "KeyPair", "vockey")

        instance_role = iam.Role.from_role_arn(self, "LabRole", "arn:aws:iam::196050880864:role/LabRole")

        instance = ec2.Instance(self, "EC2Instance",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
            machine_image=ec2.MachineImage.generic_linux({
                "us-east-1": ami.value_as_string
            }),
            vpc=vpc,
            security_group=security_group,
            key_name="vockey",
            role=instance_role  # Asignar el rol LabRole
        )


        instance.user_data.add_commands(
            'cd /var/www/html/',
            'git clone https://github.com/utec-cc-2024-2-test/websimple.git',
            'git clone https://github.com/utec-cc-2024-2-test/webplantilla.git',
            'ls -l'
        )

        CfnOutput(self, "InstanceId",
            description="ID de la instancia EC2",
            value=instance.instance_id
        )

        CfnOutput(self, "InstancePublicIP",
            description="IP pública de la instancia",
            value=instance.instance_public_ip
        )

        CfnOutput(self, "websimpleURL",
            description="URL de websimple",
            value=Fn.sub("http://${InstancePublicIP}/websimple", {
                "InstancePublicIP": instance.instance_public_ip
            })
        )

        CfnOutput(self, "webplantillaURL",
            description="URL de webplantilla",
            value=Fn.sub("http://${InstancePublicIP}/webplantilla", {
                "InstancePublicIP": instance.instance_public_ip
            })
        )
