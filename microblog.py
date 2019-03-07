from app import app, db
from app.models import User, Measure, Benchmark, Data


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Measure': Measure, 'Benchmark': Benchmark, 'Data': Data}
