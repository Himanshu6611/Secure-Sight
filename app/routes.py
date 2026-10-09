"""HTML routes; detection is delegated to shared services."""
from flask import Blueprint, render_template, current_app, send_from_directory

bp = Blueprint("main", __name__)
@bp.get("/")
def index():
    return render_template("index.html")


@bp.get("/robots.txt")
def robots_txt():
    from .seo import robots
    return robots()


@bp.get("/sitemap.xml")
def sitemap_xml():
    from .seo import sitemap
    return sitemap()


@bp.get("/favicon.ico")
def favicon():
    return send_from_directory(current_app.static_folder, "favicon.svg", mimetype="image/svg+xml")
