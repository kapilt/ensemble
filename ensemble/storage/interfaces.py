

from zope.interface import Interface


class ITransaction(Interface):

    # Transaction interface
    def begin():
        pass

    def commit():
        pass

    def abort():
        pass


class IStorage(Interface):

    # Mutator interface / CQRS Style
    def set_config(key, mapping):
        """
        """

    def update_unit_charm(svc_name, charm_url):
        """Unit charm goal state should convey the desired upgrade.

        # Returns events
        """

    def add_unit(service, machine):
        """Add a unit to the given machine.
        """

    def remove_units(unit_names):
        """Remove Units

        # Returns events
        """

    def set_annotation(entity, entity_type, key, mapping):
        """Set annotation
        # Return None
        """

    def add_machine(machine_data):
        """Set the machine.
        """

    def remove_machine(mid):
        """Remove the machine with the given id
        """

    def add_relation(rel_data):
        """Fully scoped actualized relation data to serialize
        """

    def remove_relation(rel_id):
        """Remove relation by relation id.
        """

    def remove_service(service_name):
        """Remove the given service and units
        """
#    def destroy_environment(env_id):
#        """Environment.
#        """

    # Query/Read Interface
    def annotation(entity, entity_type):
        """
        """

    def config(key):
        """Return config setting for key."""

    def machines():
        """Machines extant in the environment.
        """

    def query_machine(**terms):
        """Machine per terms.
        """

    def services():
        """Services."""

#    def units():
#        """Units."""

    def relations():
        """Relations"""

    def networks():
        """Networks."""

    def volumes():
        """Volumes allocated for use by the env."""

    def subnets():
        """Subnets."""

    def charms():
        """
        """
