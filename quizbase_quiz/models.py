from django.db import models
from django.conf import settings
from utils.base.validators import validate_special_char



class Question(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    question_text = models.CharField(
        max_length=255, validators=[validate_special_char])
    created_at = models.DateTimeField(auto_now_add=True)

    
    def __str__(self):
        return self.question_text
    

class Answer(models.Model):
    # The available choices for the answer
    QUIZ_CHOICES = (
        ('A', 'Choice A'),
        ('B', 'Choice B'),
        ('C', 'Choice C'),
        ('D', 'Choice D'),
    )

    question = models.ForeignKey(Question, on_delete=models.CASCADE)

    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    
    answer_choice = models.CharField(
        choices=QUIZ_CHOICES, max_length=1, blank=True)
    answer_text = models.CharField(
        max_length=255, validators=[validate_special_char])
    # New field to indicate correctness
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return self.answer_text
