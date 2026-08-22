"""Flask API routes for the Insider Threat Detection System."""

from flask import Blueprint, jsonify, request
from backend.services import data_service

api_bp = Blueprint('api', __name__)


@api_bp.route('/dashboard')
def dashboard():
    try:
        stats = data_service.get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/users')
def users():
    try:
        search = request.args.get('search', '')
        risk = request.args.get('risk', '')
        result = data_service.get_all_users(
            search=search if search else None,
            risk_filter=risk if risk else None
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/users/<int:user_id>')
def user_detail(user_id):
    try:
        user = data_service.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(user)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/activity')
def activity():
    try:
        search = request.args.get('search', '')
        status = request.args.get('status', '')
        limit = request.args.get('limit', 50, type=int)
        result = data_service.get_activity_logs(
            search=search if search else None,
            status_filter=status if status else None,
            limit=min(limit, 200)
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents')
def incidents():
    try:
        severity = request.args.get('severity', '')
        status = request.args.get('status', '')
        inc_type = request.args.get('type', '')
        result = data_service.get_incidents(
            severity_filter=severity if severity else None,
            status_filter=status if status else None,
            type_filter=inc_type if inc_type else None
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents/<int:incident_id>')
def incident_detail(incident_id):
    try:
        incident = data_service.get_incident_by_id(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        return jsonify(incident)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents', methods=['POST'])
def create_incident():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        incident_id, error = data_service.create_incident(data)
        if error:
            return jsonify({'error': error}), 400

        incident = data_service.get_incident_by_id(incident_id)
        return jsonify(incident), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/incidents/<int:incident_id>', methods=['PUT'])
def update_incident(incident_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        success, error = data_service.update_incident(incident_id, data)
        if not success:
            return jsonify({'error': error}), 400

        incident = data_service.get_incident_by_id(incident_id)
        return jsonify(incident)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/threat-analysis')
def threat_analysis():
    try:
        result = data_service.get_threat_analysis()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
