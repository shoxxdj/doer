def generate_custom_router(args,step):
    for content in step['content']:
        match content['type']:
            case _:
                return args.substitute_variables(content['value'])

def main(args):
        print("Hello from custom text module")
        steps = args.workflow['generate_text'].get('steps', [])
        output_blocks = []
        for step in steps:
            # 1️⃣ Vérifie si la condition WHEN existe
            when_condition = step.get('when')
            if when_condition:
                if not args.evaluate_when(when_condition):
                    args.logger.debug(f"WHEN ignoré: {when_condition}")
                    continue
            # 2️⃣ Génère le contenu si présent
            if 'content' in step:
                output_blocks.append(generate_custom_router(args,step))
        print("\n".join(output_blocks))