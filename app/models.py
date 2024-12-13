from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    data_records = db.relationship('DataRecord', backref='owner', lazy='dynamic')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 2FA fields
    two_factor_enabled = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20))
    two_factor_secret = db.Column(db.String(32))
    
    # Default encryption preference
    default_encryption_enabled = db.Column(db.Boolean, default=True)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class DataRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))  # New column for file type
    file_size = db.Column(db.Integer)     # New column for file size
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    epsilon = db.Column(db.Float, default=1.0)  # Default privacy budget
    noise_level = db.Column(db.Float, default=0.1)  # Default noise level
    
    @property
    def get_file_type(self):
        return os.path.splitext(self.filename)[1][1:].lower() if '.' in self.filename else 'unknown'

class DataShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.Integer, db.ForeignKey('data_record.id'), nullable=False)
    shared_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for public links
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=True)
    access_token = db.Column(db.String(128), unique=True, nullable=False)
    
    # Share type and limits
    is_public_link = db.Column(db.Boolean, default=False)
    download_limit = db.Column(db.Integer, nullable=True)  # None means unlimited
    download_count = db.Column(db.Integer, default=0)
    email_address = db.Column(db.String(120), nullable=True)  # For public email sharing
    
    # Custom privacy settings for this share
    privacy_epsilon = db.Column(db.Float, nullable=True)  # If null, use record's epsilon
    noise_level = db.Column(db.Float, nullable=True)     # If null, use record's noise_level
    
    # Relationships
    data_record = db.relationship('DataRecord', backref='shares')
    shared_by = db.relationship('User', foreign_keys=[shared_by_id], backref='shared_records')
    shared_with = db.relationship('User', foreign_keys=[shared_with_id], backref='received_shares')
    
    def __repr__(self):
        if self.is_public_link:
            return f'<PublicShare {self.record_id} via {self.email_address or "link"}>'
        return f'<DataShare {self.record_id} shared with {self.shared_with_id}>'
    
    @property
    def is_expired(self):
        if self.expiry_date is None:
            return False
        return datetime.utcnow() > self.expiry_date
    
    @property
    def has_reached_download_limit(self):
        if self.download_limit is None:
            return False
        return self.download_count >= self.download_limit