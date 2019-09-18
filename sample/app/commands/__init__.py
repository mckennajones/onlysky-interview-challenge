# coding: utf-8

import click


def init_app(app, db):
    @app.cli.command()
    @click.option('--uri', default=None)
    def initdb(uri):
        """Initialize the database."""

        if uri is not None:
            app.config['SQLALCHEMY_DATABASE_URI'] = uri

        db.create_all()
