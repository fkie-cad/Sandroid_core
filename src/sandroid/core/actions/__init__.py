"""ActionQ Strategy Pattern Infrastructure.

This package provides a strategy pattern implementation for the ActionQ,
enabling uniform handling of different action types (Functionality,
DataGather, string commands, etc.) through a common interface.

Architecture Overview:
    The ActionQ processes various types of items:
    - Functionality objects (Player, Recorder, Trigdroid)
    - DataGather objects (ChangedFiles, NewFiles, Processes)
    - String commands ("baseline", "load_snapshot", "interactive")

    Previously, ActionQ.do_next() used isinstance() checks to determine
    how to execute each item. The strategy pattern encapsulates this
    logic in separate strategy classes, enabling:

    1. Single Responsibility: Each strategy handles one action type
    2. Open/Closed: New action types can be added without modifying ActionQ
    3. Dependency Inversion: ActionQ depends on ActionStrategy abstraction
    4. Testability: Strategies can be mocked independently

Key Components:
    ActionStrategy (base.py):
        Abstract base class defining the strategy interface.
        All strategies must implement execute() and get_name().

    FunctionalityAdapter (adapters.py):
        Wraps Functionality objects, calling perform() on execute().

    DataGatherAdapter (adapters.py):
        Wraps DataGather objects, calling gather() on execute().
        Provides access to pretty_print() and return_data().

    StringCommandStrategy (factory.py):
        Handles string-based commands like "baseline", "load_snapshot".

    ActionFactory (factory.py):
        Creates appropriate strategies for queue items.
        Supports custom type registration for extensibility.

Usage Examples:

    Basic Usage:
        from sandroid.core.actions import ActionFactory, create_strategy

        # Using factory singleton
        factory = ActionFactory.get()

        # Create strategy from Functionality
        player = Player()
        strategy = factory.create(player)
        strategy.execute()  # Calls player.perform()

        # Create strategy from DataGather
        gatherer = ChangedFiles()
        strategy = factory.create(gatherer)
        strategy.execute()  # Calls gatherer.gather()
        print(strategy.get_formatted_output())  # From pretty_print()
        data = strategy.get_data()  # From return_data()

        # Convenience function
        strategy = create_strategy(item)

    Custom Type Registration:
        from sandroid.core.actions import register_type

        class MyCustomAction:
            def run(self):
                print("Running custom action")

        class MyCustomStrategy(ActionStrategy):
            def __init__(self, action):
                self._action = action

            def execute(self):
                self._action.run()

            def get_name(self):
                return "MyCustomAction"

        # Register the custom type
        register_type(MyCustomAction, lambda x: MyCustomStrategy(x))

        # Now factory can handle MyCustomAction
        strategy = create_strategy(MyCustomAction())

    String Command Handlers:
        from sandroid.core.actions import register_command

        def handle_my_command():
            print("Executing my command")
            return {"result": "success"}

        register_command("my_command", handle_my_command)

        # Now StringCommandStrategy will call the handler
        strategy = create_strategy("my_command")
        strategy.execute()

Migration Guide:
    To migrate existing ActionQ code to use strategies:

    1. Create strategies using the factory:
        old: self.q.append(ChangedFiles())
        new: self.q.append(factory.create(ChangedFiles()))

    2. Execute using strategy interface:
        old: if isinstance(action, DataGather):
                 action.gather()
        new: strategy.execute()

    3. Get data using strategy interface:
        old: if isinstance(q_entry, DataGather):
                 q_entry.return_data()
        new: if strategy.is_data_gatherer():
                 strategy.get_data()
"""

# Base strategy interface
# Adapter strategies for existing types
from sandroid.core.actions.adapters import (
    CallableAdapter,
    DataGatherAdapter,
    FunctionalityAdapter,
)
from sandroid.core.actions.base import ActionStrategy, AsyncActionStrategy

# Factory and string command strategy
from sandroid.core.actions.factory import (
    ActionFactory,
    StringCommandStrategy,
    create_strategy,
    register_command,
    register_type,
)

__all__ = [
    # Factory
    "ActionFactory",
    # Base classes
    "ActionStrategy",
    "AsyncActionStrategy",
    "CallableAdapter",
    "DataGatherAdapter",
    # Adapters
    "FunctionalityAdapter",
    "StringCommandStrategy",
    # Convenience functions
    "create_strategy",
    "register_command",
    "register_type",
]
