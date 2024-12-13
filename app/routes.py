import os
import random
import string
from flask import session
from flask import Blueprint, render_template, flash, redirect, url_for, request, current_app, send_from_directory, after_this_request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app.privacy import DifferentialPrivacy
import pandas as pd
import json
from app import db, bcrypt
from app.models import User, DataRecord, DataShare
from datetime import datetime, timedelta
from app.privacy import process_file_with_privacy
from flask import jsonify, request
from flask_login import login_required, current_user
from flask import current_app
from flask_mail import Message
from app import mail

# Create blueprints
main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)

@main.route('/api/settings/encryption', methods=['POST'])
@login_required
def update_encryption_settings():
    data = request.get_json()
    current_user.default_encryption_enabled = data.get('enabled', True)
    db.session.commit()
    return jsonify({'status': 'success'})

@main.route('/api/settings/phone', methods=['POST'])
@login_required
def update_phone():
    try:
        data = request.get_json()
        if not data or 'phone_number' not in data:
            return jsonify({'status': 'error', 'message': 'Phone number is required'}), 400
            
        phone_number = data.get('phone_number')
        current_user.phone_number = phone_number
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Phone number updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@main.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@main.route('/api/settings/2fa', methods=['POST'])
@login_required
def update_2fa():
    try:
        data = request.get_json()
        print(f"Updating 2FA settings for user {current_user.email}")  # Debug log
        print(f"Current 2FA status: {current_user.two_factor_enabled}")  # Debug log
        print(f"New 2FA status: {data.get('enabled')}")  # Debug log
        
        if not data or 'enabled' not in data:
            return jsonify({'status': 'error', 'message': 'Missing enabled parameter'}), 400
            
        current_user.two_factor_enabled = data['enabled']
        db.session.commit()
        print(f"2FA settings updated. New status: {current_user.two_factor_enabled}")  # Debug log
        return jsonify({'status': 'success', 'message': '2FA settings updated successfully'})
    except Exception as e:
        print(f"Error updating 2FA settings: {str(e)}")  # Debug log
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500




# Authentication routes

def generate_verification_code():
    """Generate a 6-digit verification code"""
    try:
        code = ''.join(random.choices(string.digits, k=6))
        current_app.logger.info(f"Successfully generated verification code: {code}")
        return code
    except Exception as e:
        current_app.logger.error(f"Error generating verification code: {str(e)}")
        return '123456'  # Fallback code


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('auth.register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    current_app.logger.info("=== Starting login process ===")
    
    if current_user.is_authenticated:
        current_app.logger.info("User already authenticated")
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        current_app.logger.info(f"Login attempt for email: {email}")
        
        # Try to find user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User.query.filter_by(username=email).first()
            current_app.logger.info(f"User lookup result: {'Found' if user else 'Not found'}")
        
        if user:
            current_app.logger.info(f"Found user: {user.email}")
            current_app.logger.info(f"2FA status: {user.two_factor_enabled}")
            current_app.logger.info(f"Phone number: {user.phone_number}")
        
        if user and user.check_password(password):
            current_app.logger.info("Password check passed")
            
            if user.two_factor_enabled:
                current_app.logger.info("2FA is enabled, generating code...")
                try:
                    verification_code = '123456'  # Fixed code for testing
                    current_app.logger.info(f"Generated verification code: {verification_code}")
                    
                    session['verification_code'] = verification_code
                    session['user_id'] = user.id
                    session['user_email'] = user.email
                    current_app.logger.info(f"Stored in session - code: {verification_code}, user_id: {user.id}")
                    
                    # Store code in flash message for visibility
                    flash(f'Your verification code is: {verification_code}', 'info')
                    return redirect(url_for('auth.verify_2fa'))
                except Exception as e:
                    current_app.logger.error(f"Error during 2FA process: {str(e)}")
                    flash('Error during 2FA process', 'error')
                    return render_template('login.html')
            else:
                current_app.logger.info("2FA not enabled, proceeding with login")
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('main.dashboard'))
        else:
            current_app.logger.info("Password check failed or user not found")
            flash('Invalid email/username or password', 'error')
    
    current_app.logger.info("=== End of login process ===")
    return render_template('login.html')

@auth.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    current_app.logger.info("=== Starting 2FA verification ===")
    
    if 'verification_code' not in session:
        current_app.logger.error("No verification code in session")
        flash('Verification code expired. Please login again.', 'error')
        return redirect(url_for('auth.login'))
    
    if 'user_id' not in session:
        current_app.logger.error("No user_id in session")
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        current_app.logger.error("User not found")
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        current_app.logger.info(f"Received verification code: {code}")
        current_app.logger.info(f"Expected code: {session['verification_code']}")
        
        if code and code == session['verification_code']:
            login_user(user)
            session.pop('verification_code', None)
            session.pop('user_id', None)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        flash('Invalid verification code', 'error')
    
    # Show the verification code in the template context
    return render_template('verify_2fa.html',
                         phone_number=user.phone_number,
                         verification_code=session.get('verification_code'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# Main routes
@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')

@main.route('/dashboard')
@login_required
def dashboard():
    records = DataRecord.query.filter_by(user_id=current_user.id).all()
    
    # Update file sizes if they're None
    for record in records:
        if record.file_size is None and record.file_path and os.path.exists(record.file_path):
            try:
                record.file_size = os.path.getsize(record.file_path)
            except OSError:
                record.file_size = None
    
    # Commit any file size updates
    try:
        db.session.commit()
    except:
        db.session.rollback()
    
    return render_template('dashboard.html', records=records)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'csv', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'csv', 'json'}

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            
            # Save file only once
            file.save(filepath)
            
            # Get file size and type safely
            try:
                file_size = os.path.getsize(filepath) if os.path.exists(filepath) else None
            except OSError:
                file_size = None
                
            file_type = os.path.splitext(filename)[1][1:].lower() if '.' in filename else 'unknown'
            
            # Create database record
            record = DataRecord(
                filename=filename,
                file_path=filepath,
                user_id=current_user.id,
                file_size=file_size,
                file_type=file_type
            )
            
            try:
                db.session.add(record)
                db.session.commit()
                flash('File uploaded successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error saving file record: {str(e)}', 'danger')
                # Clean up the file if database save fails
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(request.url)
                
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid file type. Please upload a CSV or JSON file.', 'danger')
            
    return render_template('upload.html')

@main.route('/view/<int:record_id>')
@login_required
def view_data(record_id):
    record = DataRecord.query.get_or_404(record_id)
    data_preview = None
    
    if record.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    try:
        # Get file size safely first
        try:
            file_size = os.path.getsize(record.file_path) if os.path.exists(record.file_path) else None
        except OSError:
            file_size = None
            
        # Ensure record has valid privacy settings
        record.epsilon = float(record.epsilon if record.epsilon is not None else 1.0)
        record.noise_level = float(record.noise_level if record.noise_level is not None else 0.1)
            
        # Initialize file_info first
        file_info = {
            'filename': record.filename,
            'upload_date': record.upload_date,
            'size': file_size if file_size and file_size > 0 else None,  # Ensure size is valid
            'privacy_level': record.epsilon,
            'noise_level': record.noise_level
        }
            
        # Process data with differential privacy
        if not os.path.exists(record.file_path):
            flash('File not found on disk.', 'danger')
            return render_template('view_data.html', 
                                 record=record, 
                                 file_info=file_info, 
                                 data=None)
            
        try:
            private_data = process_file_with_privacy(
                record.file_path,
                file_info['privacy_level'],
                file_info['noise_level']
            )
            
            # Convert data to HTML table or JSON preview
            if isinstance(private_data, pd.DataFrame):
                data_preview = private_data.head(100).to_html(
                    classes='table table-striped table-hover',
                    index=False,
                    escape=False,
                    float_format=lambda x: '{:.2f}'.format(x) if isinstance(x, float) else x
                )
            else:  # JSON data
                data_preview = f'<pre class="json-preview">{json.dumps(private_data, indent=2)}</pre>'
        except Exception as e:
            flash(f'Error processing file data: {str(e)}', 'warning')
            data_preview = None
        
        return render_template('view_data.html', 
                             record=record, 
                             file_info=file_info, 
                             data=data_preview)
    except Exception as e:
        flash(f'Error accessing file: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))
   
@main.route('/search-files')
@login_required
def search_files():
    query = request.args.get('query', '')
    file_type = request.args.get('file_type', '')
    date_from_str = request.args.get('date_from', '')
    date_to_str = request.args.get('date_to', '')
    
    # Start with base query
    files_query = DataRecord.query.filter_by(user_id=current_user.id)
    
    # Apply search filters
    if query:
        files_query = files_query.filter(DataRecord.filename.ilike(f'%{query}%'))
    
    if file_type:
        files_query = files_query.filter(DataRecord.file_type == file_type)
    
    # Parse dates and apply filters
    date_from = None
    date_to = None
    
    if date_from_str:
        try:
            date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
            files_query = files_query.filter(DataRecord.upload_date >= date_from)
        except ValueError:
            pass
    
    if date_to_str:
        try:
            date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
            files_query = files_query.filter(DataRecord.upload_date <= date_to)
        except ValueError:
            pass
    
    # Execute query and get results
    files = files_query.order_by(DataRecord.upload_date.desc()).all()
    
    # Update file sizes if they're None
    for file in files:
        if file.file_size is None and file.file_path and os.path.exists(file.file_path):
            try:
                file.file_size = os.path.getsize(file.file_path)
            except OSError:
                file.file_size = None
    
    # Get unique file types for filter dropdown
    file_types = db.session.query(DataRecord.file_type)\
        .filter_by(user_id=current_user.id)\
        .distinct()\
        .all()
    file_types = [ft[0] for ft in file_types if ft[0]]
    
    return render_template('search_files.html', 
                         files=files, 
                         query=query,
                         file_types=file_types,
                         selected_type=file_type,
                         date_from=date_from_str,  # Pass original string values
                         date_to=date_to_str)      # Pass original string values

@main.route('/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    record = DataRecord.query.get_or_404(record_id)
    
    if record.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    try:
        # Delete the actual file
        if os.path.exists(record.file_path):
            os.remove(record.file_path)
        
        # Delete the database record
        db.session.delete(record)
        db.session.commit()
        flash('Record deleted successfully!', 'success')
    except Exception as e:
        flash('Error deleting record.', 'danger')
        
    return redirect(url_for('main.dashboard'))

@main.route('/shared-with-me')
@login_required
def shared_with_me():
    shared_records = DataShare.query.filter_by(shared_with_id=current_user.id).all()
    return render_template('shared_with_me.html', shares=shared_records)
@main.route('/view-shared/<int:share_id>')
@login_required
def view_shared(share_id):
    share = DataShare.query.get_or_404(share_id)
    if share.shared_with_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    data_record = share.data_record
    privacy_settings = {
        'epsilon': share.privacy_epsilon or data_record.epsilon,
        'noise_level': share.noise_level or data_record.noise_level
    }
    
    try:
        if data_record.file_type == 'csv':
            df = pd.read_csv(os.path.join(current_app.config['UPLOAD_FOLDER'], data_record.file_path))
        else:
            with open(os.path.join(current_app.config['UPLOAD_FOLDER'], data_record.file_path)) as f:
                df = pd.DataFrame(json.load(f))
        
        dp = DifferentialPrivacy(epsilon=privacy_settings['epsilon'], noise_level=privacy_settings['noise_level'])
        df_preview = dp.process_dataframe(df)
        df_preview = df_preview.head(10)
        
        # Convert DataFrame to HTML table
        preview_data = df_preview.to_html(
            classes='table table-striped table-hover',
            index=False,
            escape=False,
            float_format=lambda x: '{:.2f}'.format(x) if isinstance(x, float) else x
        )
    except Exception as e:
        preview_data = None
        flash(f'Error loading preview: {str(e)}', 'warning')
    
    return render_template('view_shared.html', 
                         share=share,
                         data_record=data_record,
                         privacy_settings=privacy_settings,
                         preview_data=preview_data)

@main.route('/my-shared-files')
@login_required
def my_shared_files():
    # Get all shares where the current user is the sharer
    shared_files = DataShare.query.filter_by(shared_by_id=current_user.id).all()
    
    # Create a list of shared file details
    shared_file_details = []
    for share in shared_files:
        shared_with = share.shared_with.username if share.shared_with else (
            f"Public Link ({share.email_address})" if share.email_address else "Public Link"
        )
        
        shared_file_details.append({
            'filename': share.data_record.filename,
            'shared_with': shared_with,
            'shared_date': share.created_at,
            'expiry_date': share.expiry_date,
            'record_id': share.record_id,
            'share_id': share.id,
            'is_public': share.is_public_link,
            'download_count': share.download_count if share.is_public_link else None,
            'download_limit': share.download_limit if share.is_public_link else None
        })
    
    return render_template('my_shared_files.html', shared_files=shared_file_details)



@main.route('/delete-share/<int:share_id>', methods=['POST'])
@login_required
def delete_share(share_id):
    share = DataShare.query.get_or_404(share_id)
    
    # Check if the current user is the one who shared the file
    if share.shared_by_id != current_user.id:
        flash('You do not have permission to revoke this share.', 'danger')
        return redirect(url_for('main.my_shared_files'))
    
    db.session.delete(share)
    db.session.commit()
    
    flash('Share access has been revoked successfully.', 'success')
    return redirect(url_for('main.my_shared_files'))

@main.route('/download-shared/<int:share_id>')
@login_required
def download_shared(share_id):
    share = DataShare.query.get_or_404(share_id)
    if share.shared_with_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    data_record = share.data_record
    privacy_settings = {
        'epsilon': share.privacy_epsilon or data_record.epsilon,
        'noise_level': share.noise_level or data_record.noise_level
    }
    
    try:
        # Apply differential privacy to the data
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], data_record.file_path)
        if data_record.file_type == 'csv':
            df = pd.read_csv(file_path)
            dp = DifferentialPrivacy(epsilon=privacy_settings['epsilon'], noise_level=privacy_settings['noise_level'])
            private_data = dp.process_dataframe(df)
            
            # Save to temporary file
            temp_filename = f'private_{data_record.filename}'
            temp_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
            private_data.to_csv(temp_filepath, index=False)
            
            @after_this_request
            def remove_file(response):
                try:
                    os.remove(temp_filepath)
                except Exception as e:
                    print(f"Error removing temporary file: {e}")
                return response
            
            return send_from_directory(
                current_app.config['UPLOAD_FOLDER'],
                temp_filename,
                as_attachment=True,
                download_name=f'private_{data_record.filename}'
            )
        else:  # JSON file
            with open(file_path) as f:
                data = json.load(f)
            df = pd.DataFrame(data)
            dp = DifferentialPrivacy(epsilon=privacy_settings['epsilon'], noise_level=privacy_settings['noise_level'])
            private_data = dp.process_dataframe(df)
            
            # Save to temporary file
            temp_filename = f'private_{data_record.filename}'
            temp_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
            private_data.to_json(temp_filepath, orient='records', indent=2)
            
            @after_this_request
            def remove_file(response):
                try:
                    os.remove(temp_filepath)
                except Exception as e:
                    print(f"Error removing temporary file: {e}")
                return response
            
            return send_from_directory(
                current_app.config['UPLOAD_FOLDER'],
                temp_filename,
                as_attachment=True,
                download_name=f'private_{data_record.filename}'
            )
    except Exception as e:
        flash(f'Error processing download: {str(e)}', 'danger')
        return redirect(url_for('main.shared_with_me'))

@main.route('/download/<int:record_id>')
@login_required
def download_data(record_id):
    record = DataRecord.query.get_or_404(record_id)
    
    if record.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    format_type = request.args.get('format', 'csv')
    directory = os.path.dirname(record.file_path)
    filename = os.path.basename(record.file_path)
    
    return send_from_directory(
        directory,
        filename,
        as_attachment=True,
        download_name=f"{os.path.splitext(filename)[0]}.{format_type}"
    )

@main.route('/share/<int:record_id>', methods=['GET', 'POST'])
@login_required
def share_data(record_id):
    record = DataRecord.query.get_or_404(record_id)
    
    # Verify ownership
    if record.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        shared_with_username = request.form.get('username')
        shared_with = User.query.filter_by(username=shared_with_username).first()
        
        if not shared_with:
            flash('User not found.', 'danger')
            return redirect(url_for('main.share_data', record_id=record_id))
            
        if shared_with.id == current_user.id:
            flash('Cannot share with yourself.', 'danger')
            return redirect(url_for('main.share_data', record_id=record_id))
            
        # Check if already shared
        existing_share = DataShare.query.filter_by(
            record_id=record_id,
            shared_with_id=shared_with.id
        ).first()
        
        if existing_share:
            flash('Already shared with this user.', 'warning')
            return redirect(url_for('main.share_data', record_id=record_id))
        
        # Create new share
        # Create new share with default values if attributes don't exist
        share = DataShare(
            record_id=record_id,
            shared_by_id=current_user.id,
            shared_with_id=shared_with.id,
            privacy_epsilon=float(request.form.get('epsilon', 1.0)),  # Default to 1.0
            noise_level=float(request.form.get('noise_level', 0.1)),  # Default to 0.1
            access_token=os.urandom(16).hex()
        )
        
        # Set expiry if provided
        expiry_days = request.form.get('expiry_days')
        if expiry_days:
            share.expiry_date = datetime.utcnow() + timedelta(days=int(expiry_days))
        
        db.session.add(share)
        db.session.commit()
        
        flash(f'Successfully shared with {shared_with_username}!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('share.html', record=record)

@main.route('/create-public-share/<int:record_id>', methods=['POST'])
@login_required
def create_public_share(record_id):
    record = DataRecord.query.get_or_404(record_id)
    
    # Check if user owns the record
    if record.user_id != current_user.id:
        flash('You do not have permission to share this file.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    data = request.form
    email = data.get('email')
    download_limit = data.get('download_limit')
    expiry_days = data.get('expiry_days')
    
    # Generate unique access token
    access_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    # Calculate expiry date if specified
    expiry_date = None
    if expiry_days:
        expiry_date = datetime.utcnow() + timedelta(days=int(expiry_days))
    
    # Create public share
    share = DataShare(
        record_id=record.id,
        shared_by_id=current_user.id,
        is_public_link=True,
        email_address=email,
        download_limit=int(download_limit) if download_limit else None,
        expiry_date=expiry_date,
        access_token=access_token
    )
    
    db.session.add(share)
    db.session.commit()
    
    # Generate share link
    share_link = url_for('main.access_public_share', token=access_token, _external=True)
    
    # If email is provided, send the link
    if email:
        try:
            # Add email sending logic here
            msg = Message(
                'File Shared with You',
                sender=current_app.config['MAIL_DEFAULT_SENDER'],
                recipients=[email]
            )
            msg.body = f'''A file has been shared with you.
            
Click the link below to access the file:
{share_link}

This link {'expires on ' + expiry_date.strftime('%Y-%m-%d %H:%M') if expiry_date else 'does not expire'}.
{'Download limit: ' + str(download_limit) + ' downloads' if download_limit else 'No download limit.'}
'''
            mail.send(msg)
            flash(f'Share link has been sent to {email}', 'success')
        except Exception as e:
            flash(f'Failed to send email: {str(e)}', 'danger')
    
    return jsonify({
        'status': 'success',
        'share_link': share_link,
        'message': 'Share link created successfully'
    })

@main.route('/access-public-share/<token>')
def access_public_share(token):
    share = DataShare.query.filter_by(access_token=token).first_or_404()
    
    # Check if share is expired
    if share.is_expired:
        flash('This share link has expired.', 'danger')
        return redirect(url_for('main.index'))
    
    # Check download limit
    if share.has_reached_download_limit:
        flash('This share link has reached its download limit.', 'danger')
        return redirect(url_for('main.index'))
    
    # Increment download count
    share.download_count += 1
    db.session.commit()
    
    # Display file or download page
    return render_template('public_share.html', share=share)
@main.route('/update-file-sizes')
@login_required
def update_file_sizes():
    try:
        records = DataRecord.query.filter_by(user_id=current_user.id).all()
        updated_count = 0
        
        for record in records:
            if record.file_path and os.path.exists(record.file_path):
                record.file_size = os.path.getsize(record.file_path)
                record.file_type = os.path.splitext(record.filename)[1][1:].lower() if '.' in record.filename else 'unknown'
                updated_count += 1
        
        db.session.commit()
        flash(f'Successfully updated {updated_count} file(s)', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating file sizes: {str(e)}', 'danger')
    
    return redirect(url_for('main.dashboard'))
