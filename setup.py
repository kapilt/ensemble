from setuptools import setup

setup(name='ensemble',
      version="0.1",
      classifiers=[
          'Intended Audience :: Developers',
          'Programming Language :: Python',
          'Operating System :: OS Independent'],
      author='Kapil Thangavelu',
      author_email='kapil.foss@gmail.com',
      description="",
      long_description=open("readme.md").read(),
      url='https://github.com/kapilt/ensemble',
      license='BSD',
      py_modules=['ensemble'],
      install_requires=["PyYAML"],
      )
