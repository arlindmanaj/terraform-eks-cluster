provider "aws" {
 alias = "primary"
  region = "eu-north-1" 
}
provider "aws" {
  alias  = "secondary"
  region = "us-east-1" # Region for the replica bucket
}

# VPC
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "terraform-vpc"
  }
}

# VPC Endpoint for S3
resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.eu-north-1.s3"
  route_table_ids   = [aws_route_table.private.id] # Attach to private route table
  vpc_endpoint_type = "Gateway"

  tags = {
    Name = "s3-vpc-endpoint"
  }
}


# Public Subnet in Availability Zone A
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.38.0/24"
  availability_zone       = "eu-north-1a"
  map_public_ip_on_launch = true
  

  tags = {
    Name = "public-subnet-a"
  }
}

# Private Subnet in Availability Zone B
resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.39.0/24"
  availability_zone       = "eu-north-1b"

  tags = {
    Name = "private-subnet-b"
  }
}

# Private Subnet in AZ C
resource "aws_subnet" "private_c" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.41.0/24"
  availability_zone       = "eu-north-1a"

  tags = {
    Name = "private-subnet-c"
  }
}

# Private Subnet in AZ D
resource "aws_subnet" "private_d" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.40.0/24"
  availability_zone       = "eu-north-1b"
  

  tags = {
    Name = "private-subnet-d"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "internet-gateway"
  }
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

# Associate Public Subnet with Public Route Table
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "private-route-table"
  }
}

# Associate Private Subnet with Private Route Table

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_c" {
  subnet_id      = aws_subnet.private_c.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_d" {
  subnet_id      = aws_subnet.private_d.id
  route_table_id = aws_route_table.private.id
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  provider = aws.primary
  domain = "vpc"

  tags = {
    Name = "nat-eip"
  }
}

# NAT Gateway
resource "aws_nat_gateway" "nat" {
  provider = aws.primary
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id

  tags = {
    Name = "nat-gateway"
  }
}


# Security Group for EKS
resource "aws_security_group" "eks" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 1025
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-security-group"
  }
}

# Bastion Host Security Group
resource "aws_security_group" "bastion_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["193.167.77.0/24"] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion-sg"
  }
}

# Security Group for Database
resource "aws_security_group" "database" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 3306 # Example for MySQL, change as per your database port
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private_b.cidr_block, aws_subnet.private_c.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # Allow all outbound traffic
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database-security-group"
  }
}

# Security Group for EC2 Instances
resource "aws_security_group" "ec2" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22 # SSH access
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["193.167.77.0/24"] # Replace with your public IP range
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # IP te caktuara nga organizata per qasje te limitizuar.
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow HTTPS traffic
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ec2-security-group"
  }
}

# IAM Role for EKS Cluster
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "eks.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "eks_pod_role" {
  name = "eks-pod-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks_oidc.arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            "${data.aws_eks_cluster.my_cluster.identity.oidc.issuer}:sub": "system:serviceaccount:default:my-service-account"
          }
        }
      }
    ]
  })
}


# IAM Cluster Policies
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_service_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

# IAM Role for Worker Nodes
resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Worker Node Policies
resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "ec2_container_registry_read_only" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

# IAM Role for AWS Backup
resource "aws_iam_role" "backup_role" {
  name = "backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "backup.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach Permissions to Backup Role
resource "aws_iam_role_policy_attachment" "backup_policy_attachment" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

# IAM Role for S3 Application Role
resource "aws_iam_role" "s3_replication_role" {
  name = "s3-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "s3_replication_attachment" {
  role       = aws_iam_role.s3_replication_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonS3ReplicationPolicy"
}

# Bastion Host Instance
resource "aws_instance" "bastion_host" {
  ami           = "ami-00b3234e97386251c" # eu-north-1 reion
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_a.id
  key_name      = "my-key-pair" 

  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "bastion-host"
  }
}

# EKS Cluster
resource "aws_eks_cluster" "my_cluster" {
  name     = "my-eks-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = [aws_subnet.private_b.id, aws_subnet.private_c.id]
  }
}

data "aws_eks_cluster" "my_cluster" {
  name = aws_eks_cluster.my_cluster.name
}

data "aws_eks_cluster_auth" "my_cluster" {
  name = aws_eks_cluster.my_cluster.name
}


# Enable IAM OIDC Provider for EKS
resource "aws_iam_openid_connect_provider" "eks_oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.aws_eks_cluster.my_cluster.identity.oidc.issuer]
  url             = data.aws_eks_cluster.my_cluster.identity.oidc.issuer
}


# Worker Nodes
resource "aws_eks_node_group" "worker_nodes" {
  cluster_name    = aws_eks_cluster.my_cluster.name
  node_group_name = "worker-nodes"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private_b.id, aws_subnet.private_c.id]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
}

resource "aws_db_instance" "test_database" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro" # Free-tier eligible
  username             = "admin"
  password             = "testpassword"
  parameter_group_name = "default.mysql8.0"
  skip_final_snapshot  = true


  backup_retention_period = 7  # Retain backups for 7 days
  backup_window           = "03:00-04:00"  # Run backups at 3 AM UTC

  multi_az = true  # Enable Multi-AZ deployment for failover protection

  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  tags = {
    Name = "test-database"
  }
}
resource "aws_db_instance" "test_database_replica" {
  replicate_source_db = aws_db_instance.test_database.id
  instance_class      = "db.t3.micro"
  storage_type        = "gp2"
  publicly_accessible = false

  tags = {
    Name = "test-database-replica"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "test-db-subnet-group"
  subnet_ids = [aws_subnet.private_b.id, aws_subnet.private_c.id]

  tags = {
    Name = "test-db-subnet-group"
  }
}

resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ec2.id]
  subnets            = [aws_subnet.public_a.id]

  tags = {
    Name = "app-load-balancer"
  }
}

resource "aws_lb_target_group" "app_tg" {
  name     = "app-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = {
    Name = "app-target-group"
  }
}

# HTTP Listener for Redirection
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}


# S3 Buckets
resource "aws_s3_bucket" "backup_bucket" {
  provider = aws.primary
  bucket = "my-disaster-recovery-bucket"
  
}

resource "aws_s3_bucket_lifecycle_configuration" "backup_bucket_lifecycle" {
  bucket = aws_s3_bucket.backup_bucket.id

  rule {
    id     = "expire-old-backups"
    status = "Enabled"

    expiration {
      days = 30  # Delete backups after 30 days
    }
  }
}

resource "aws_s3_bucket_versioning" "backup_bucket_versioning" {
  bucket = aws_s3_bucket.backup_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_acl" "backup_bucket_acl" {
  bucket = aws_s3_bucket.backup_bucket.id
  acl    = "private"
}


#Replica bucket in different region (US)

resource "aws_s3_bucket" "replica_bucket" {
  provider = aws.secondary
  bucket = "my-backup-replica-bucket"
  
}
resource "aws_s3_bucket_acl" "replica_bucket_acl" {
  bucket = aws_s3_bucket.replica_bucket.id
  acl    = "private"
}


# Create AWS Backup Vault
resource "aws_backup_vault" "backup_vault" {
  name = "my-backup-vault"
}

# Define Backup Plan
resource "aws_backup_plan" "backup_plan" {
  name = "daily-backup"

  rule {
    rule_name         = "daily-backup-rule"
    target_vault_name = aws_backup_vault.backup_vault.name
    schedule          = "cron(0 3 * * ? *)"  # Runs every day at 3 AM UTC
    start_window      = 60  # Start within 1 hour
    completion_window = 120  # Complete within 2 hours
    lifecycle {
      delete_after = 30  # Retain backups for 30 days
    }
  }
}

# Assign Backup to EC2 Instances
resource "aws_backup_selection" "backup_selection" {
  name         = "backup-selection"
  iam_role_arn = aws_iam_role.backup_role.arn
  plan_id      = aws_backup_plan.backup_plan.id

  resources = [
    aws_instance.bastion_host.arn,
    aws_eks_node_group.worker_nodes.arn,
    aws_lb.app_lb.arn,
    aws_db_instance.test_database.arn,
    aws_s3_bucket.backup_bucket.arn
  ]
}


# AWS WAF Web ACL
resource "aws_wafv2_web_acl" "web_acl" {
  count       = length(data.aws_wafv2_web_acl.existing.id) > 0 ? 0 : 1 # If block for the existing Web ACL
  name        = "example-web-acl"
  scope       = "REGIONAL" # Use "CLOUDFRONT" for global distributions
  description = "WAF ACL for the application"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "web-acl"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "allow-specific-countries"
    priority = 1

    action {
      allow {}
    }

    statement {
      geo_match_statement {
        country_codes = ["US", "GB", "DE"] # Replace with allowed countries
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "allow-specific-countries"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "block-sql-injection"
    priority = 2

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          query_string {}
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "block-sql-injection"
      sampled_requests_enabled   = true
    }
  }
}

# Check for existing Web ACL
data "aws_wafv2_web_acl" "existing" {
  name  = "example-web-acl"
  scope = "REGIONAL"
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-log-bucket"
  
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "retain-logs"
    status = "Enabled"

    expiration {
      days = 365  # Keep logs for 1 year
    }
  }
}

resource "aws_s3_bucket_acl" "cloudtrail_logs_acl" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  acl    = "private"
}


resource "aws_cloudtrail" "my_trail" {
  name                          = "cloud-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_block" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_guardduty_detector" "guardduty" {
  enable = true
}


resource "aws_shield_protection" "my_protection" {
  name         = "ShieldProtection"
  resource_arn = aws_lb.app_lb.arn  
}


resource "aws_s3_bucket_replication_configuration" "replication" {
  role   = aws_iam_role.s3_replication_role.arn
  bucket = aws_s3_bucket.backup_bucket.id

  rule {
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.replica_bucket.arn
      storage_class = "STANDARD"
    }
  }
}

# IAM Policy for S3 Backup Access
resource "aws_iam_policy" "s3_backup_policy" {
  name        = "s3-backup-policy"
  description = "Allows backup system to write to S3"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
        Resource = "${aws_s3_bucket.backup_bucket.arn}/*"
      },
      {
        Effect   = "Deny",
        Principal = "*",
        Action   = "s3:*",
        Resource = "${aws_s3_bucket.backup_bucket.arn}/*",
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce": aws_vpc_endpoint.s3_endpoint.id # Allow only from VPC Endpoint
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "backup_bucket_policy" {
  bucket = aws_s3_bucket.backup_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_role.s3_replication_role.arn
        },
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.backup_bucket.arn,
          "${aws_s3_bucket.backup_bucket.arn}/*"
        ]
        
      }
    ]
  })
}


resource "aws_iam_policy" "s3_replication_policy" {
  name        = "s3-replication-policy"
  description = "Policy for S3 replication"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.backup_bucket.arn,
          "${aws_s3_bucket.backup_bucket.arn}/*",
          aws_s3_bucket.replica_bucket.arn,
          "${aws_s3_bucket.replica_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_replication_policy_attachment" {
  role       = aws_iam_role.s3_replication_role.name
  policy_arn = aws_iam_policy.s3_replication_policy.arn
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
