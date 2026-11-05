import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('evaluation',pathlib.Path(__file__).with_name('evaluate_clamav.py')); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class EvaluationTests(unittest.TestCase):
    def test_confusion_matrix_keeps_unknowns_separate(self):
        rows=[{'malicious':True,'status':'detected'},{'malicious':False,'status':'detected'},{'malicious':True,'status':'no_known_match'},{'malicious':False,'status':'no_known_match'},{'malicious':True,'status':'error'}]
        result=module.measure(rows);self.assertEqual(result['precision'],.5);self.assertEqual(result['recall_assessed'],.5);self.assertEqual(result['assessment_coverage'],.8);self.assertEqual(result['unknown'],1)
    def test_empty_is_not_perfect_accuracy(self): self.assertIsNone(module.measure([])['precision'])
if __name__=='__main__':unittest.main()
